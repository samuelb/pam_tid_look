/*
 * dialog_check: shows whether the prompt text reaches the authorization
 * dialog, and whether the dialog closes when the timeout runs out.
 *
 * The dialog's text cannot be read without Screen Recording or Accessibility
 * permission, but its size can, and the dialog grows with the text it shows.
 * So each prompt check raises the dialog twice, with a short and a long text,
 * and compares the heights:
 *
 *   right  An undefined right (Apple's "default" rule), requested by this
 *          program with no prompt and then with a six-line prompt.
 *   sudo   The installed module: `sudo -k /usr/bin/true`, then the same with
 *          40 extra arguments. Only the module's prompt depends on argv.
 *
 * Each of these dialogs is left open for about two seconds and then withdrawn
 * by killing the process that asked for it; authd then closes the dialog.
 *
 * The timeout checks leave the dialog alone and wait for it to close by
 * itself:
 *
 *   right  The same undefined right, requested through the module's own
 *          tidcmd_authorize() with timeout=3.
 *   sudo   `sudo -k /usr/bin/true` with the timeout set in sudo_local. It is
 *          skipped when that is 0 (no timeout) or over 60 seconds.
 *
 * Ctrl-C stops the check and withdraws the open dialog by killing the process
 * that asked. There is no need to answer anything. If a dialog is approved
 * anyway, sudo runs `/usr/bin/true` as root, or the default rule leaves an
 * admin credential that the session shares for five minutes. The program
 * destroys that credential: see purge_shared_credential(). Only killing this
 * program with SIGKILL skips the cleanup.
 */

#import <CoreGraphics/CoreGraphics.h>
#import <errno.h>
#import <Foundation/Foundation.h>
#import <Security/Authorization.h>
#import <Security/AuthorizationTags.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <signal.h>
#import <spawn.h>
#import <sys/wait.h>

extern char **environ;

/* From pam_tidcmd.m, which is linked in. */
unsigned tidcmd_timeout(int argc, const char **argv);
OSStatus tidcmd_authorize(const char *rightName, const char *prompt, unsigned timeout);

static const char *kProbeRight = "com.github.pam-tidcmd.dialog-check";
static const unsigned kProbeTimeout = 3;
static const unsigned kMaxSudoTimeout = 60; /* longer configured timeouts are not waited for */

/* Set on Ctrl-C and the like. The open dialog is then withdrawn as usual and the check stops. */
static volatile sig_atomic_t stopSignal;

static void interrupted(int sig) {
    stopSignal = sig;
}

/* Child mode: ask for the probe right, optionally with a prompt. */
static int request_right(const char *prompt) {
    AuthorizationRef auth = NULL;
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &auth) != errAuthorizationSuccess) return 2;
    AuthorizationItem right = {kProbeRight, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    AuthorizationItem promptItem = {kAuthorizationEnvironmentPrompt, prompt ? strlen(prompt) : 0, (void *)prompt, 0};
    AuthorizationEnvironment environment = {prompt ? 1 : 0, prompt ? &promptItem : NULL};
    OSStatus status = AuthorizationCopyRights(auth, &rights, &environment,
        kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    /* The default rule shares its credential with the session for five minutes. Destroy it. */
    AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
    return status == errAuthorizationSuccess ? 0 : 1;
}

/*
 * Child mode: ask for the probe right the way the module asks for sudo's,
 * with the given option (timeout=N). Exits 0 if the request ended the way a
 * dismissed one does (errAuthorizationDenied).
 */
static int authorize_like_module(const char *option, const char *prompt) {
    OSStatus status = tidcmd_authorize(kProbeRight, prompt, tidcmd_timeout(1, &option));
    return status == errAuthorizationDenied ? 0 : 1;
}

/*
 * If someone approved a dialog for the probe right, the default rule put an
 * admin credential into the session, and the child that asked may have been
 * killed before it could destroy it. Take the credential over without any UI
 * (no interaction flag, so no dialog can appear) and destroy it.
 */
static void purge_shared_credential(void) {
    AuthorizationRef auth = NULL;
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &auth) != errAuthorizationSuccess) return;
    AuthorizationItem right = {kProbeRight, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    OSStatus status = AuthorizationCopyRights(auth, &rights, NULL, kAuthorizationFlagExtendRights, NULL);
    AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
    if (status == errAuthorizationSuccess) {
        printf("  (an approved dialog had left a shared admin credential; it was destroyed)\n");
    }
}

/* On-screen SecurityAgent windows, by window number. */
static NSDictionary<NSNumber *, NSValue *> *agent_windows(void) {
    NSMutableDictionary *found = [NSMutableDictionary dictionary];
    NSArray *list = CFBridgingRelease(CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID));
    for (NSDictionary *window in list) {
        if (![window[(id)kCGWindowOwnerName] isEqualToString:@"SecurityAgent"]) continue;
        CGRect bounds;
        if (!CGRectMakeWithDictionaryRepresentation((CFDictionaryRef)window[(id)kCGWindowBounds], &bounds)) continue;
        found[window[(id)kCGWindowNumber]] = [NSValue valueWithRect:NSRectFromCGRect(bounds)];
    }
    return found;
}

/* A SecurityAgent window that is not among the given ones, or nil. */
static NSNumber *new_window(NSSet *before, NSDictionary<NSNumber *, NSValue *> *now) {
    for (NSNumber *key in now) {
        if (![before containsObject:key]) return key;
    }
    return nil;
}

/* Waits up to the given time for the child to end. Stores its wait status if status is not NULL. */
static BOOL reaped(pid_t pid, int tenths, int *status) {
    for (int tick = 0; tick <= tenths; tick++) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid || (r == -1 && errno == ECHILD)) return YES;
        if (tick < tenths) usleep(100 * 1000);
    }
    return NO;
}

/* Starts argv[0] with no terminal and output to /dev/null. Returns 0 if it could not. */
static pid_t start(NSString *label, char *const argv[]) {
    posix_spawn_file_actions_t files;
    posix_spawn_file_actions_init(&files);
    for (int fd = 0; fd <= 2; fd++) {
        posix_spawn_file_actions_addopen(&files, fd, "/dev/null", fd == 0 ? O_RDONLY : O_WRONLY, 0);
    }
    /* A new session has no controlling terminal, so sudo cannot fall back to asking for a password there. */
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    pid_t pid;
    int err = posix_spawn(&pid, argv[0], &files, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&files);
    posix_spawnattr_destroy(&attr);
    if (err) {
        printf("  %-24s could not start %s: %s\n", label.UTF8String, argv[0], strerror(err));
        return 0;
    }
    return pid;
}

/*
 * Ends the child if it is still running, then waits for its dialog to close.
 * Returns NO, after saying so, if either is still there.
 */
static BOOL cleaned_up(NSString *label, pid_t pid, BOOL exited, NSNumber *windowID) {
    if (!exited) {
        /* SIGKILL, because sudo catches SIGINT and SIGTERM until authentication is over. */
        kill(pid, SIGKILL);
        if (!reaped(pid, 50, NULL)) {
            printf("  %-24s could not end process %d; end it, then cancel its dialog\n", label.UTF8String, pid);
            return NO;
        }
    }
    BOOL lingering = NO;
    for (int tick = 0; tick < 30 && (lingering = windowID && agent_windows()[windowID]); tick++) usleep(100 * 1000);
    if (lingering) {
        printf("  %-24s the dialog is still open; cancel it\n", label.UTF8String);
        return NO;
    }
    return YES;
}

/* Returned by dialog_height() when a process or dialog could not be ended. */
static const CGFloat kCleanupFailed = -1;

/*
 * Starts the process, waits for a new SecurityAgent window whose size has
 * settled, then ends the process and waits for the window to close.
 * Returns the window height, 0 if no dialog appeared, or kCleanupFailed.
 */
static CGFloat dialog_height(NSString *label, char *const argv[]) {
    NSSet *before = [NSSet setWithArray:agent_windows().allKeys];
    pid_t pid = start(label, argv);
    if (!pid) return 0;

    NSNumber *windowID = nil;
    NSRect last = NSZeroRect;
    int steady = 0;
    BOOL exited = NO, closed = NO;
    for (int tick = 0; tick < 80 && steady < 5 && !stopSignal; tick++) { /* up to 8 seconds */
        usleep(100 * 1000);
        if (waitpid(pid, NULL, WNOHANG) == pid) {
            exited = YES;
            break;
        }
        NSDictionary<NSNumber *, NSValue *> *now = agent_windows();
        if (!windowID) {
            windowID = new_window(before, now);
            continue;
        }
        if (!now[windowID]) {
            closed = YES; /* cancelled or approved by someone */
            break;
        }
        NSRect rect = now[windowID].rectValue;
        steady = NSEqualRects(rect, last) ? steady + 1 : 0;
        last = rect;
    }

    /* If someone answered the dialog, let the child finish, so it can destroy what it was granted. */
    if (!exited && closed) exited = reaped(pid, 30, NULL);
    if (!cleaned_up(label, pid, exited, windowID)) return kCleanupFailed;

    if (steady < 5) {
        printf("  %-24s %s\n", label.UTF8String,
            closed ? "the dialog closed before it could be measured" :
            exited ? "no dialog appeared (the process ended on its own)" : "no dialog appeared");
        return 0;
    }
    printf("  %-24s dialog %.0f x %.0f\n", label.UTF8String, last.size.width, last.size.height);
    return last.size.height;
}

enum { kPass = 0, kFail = 1, kInconclusive = 2, kStopped = 3 };

/*
 * Starts the process and leaves its dialog alone. Passes if the dialog
 * closes by itself once the timeout has run out, and the process then exits
 * by itself with the given status.
 */
static int closes_by_itself(NSString *label, char *const argv[], unsigned timeout, int wantExit, const char *what) {
    NSSet *before = [NSSet setWithArray:agent_windows().allKeys];
    pid_t pid = start(label, argv);
    if (!pid) return kInconclusive;

    NSDate *started = [NSDate date];
    NSNumber *windowID = nil;
    BOOL exited = NO, closed = NO;
    int status = 0;
    while (!stopSignal && -started.timeIntervalSinceNow < timeout + 10) {
        usleep(100 * 1000);
        NSDictionary<NSNumber *, NSValue *> *now = agent_windows();
        if (!windowID) {
            windowID = new_window(before, now);
            if (!windowID && waitpid(pid, &status, WNOHANG) == pid) {
                exited = YES;
                break;
            }
            continue;
        }
        if (!now[windowID]) {
            closed = YES;
            break;
        }
    }
    NSTimeInterval openFor = -started.timeIntervalSinceNow;

    /*
     * After the dialog closes, the process should end by itself. sudo finds
     * no terminal to ask for the password on and exits with status 1; exit
     * status 0 would mean it ran the command.
     */
    if (closed) exited = reaped(pid, 50, &status);
    BOOL endedByItself = exited;
    if (!cleaned_up(label, pid, exited, windowID)) return kStopped;
    if (stopSignal) return kStopped;

    const char *name = label.UTF8String;
    int verdict;
    if (!windowID) {
        printf("  %-24s no dialog appeared\n", name);
        verdict = kInconclusive;
    } else if (!closed) {
        printf("  %-24s the dialog was still open after %.0f s\n", name, openFor);
        verdict = kFail;
    } else if (openFor < timeout - 0.5) {
        printf("  %-24s the dialog closed after %.1f s, before the timeout; was it answered?\n", name, openFor);
        verdict = kInconclusive;
    } else if (!endedByItself) {
        printf("  %-24s the dialog closed after %.1f s, but the process kept running\n", name, openFor);
        verdict = kFail;
    } else {
        BOOL normal = WIFEXITED(status);
        int code = normal ? WEXITSTATUS(status) : WTERMSIG(status);
        printf("  %-24s the dialog closed by itself after %.1f s; %s %d (expected exit status %d)\n",
            name, openFor, normal ? "exit status" : "killed by signal", code, wantExit);
        verdict = normal && code == wantExit ? kPass : kFail;
    }
    printf("  -> %s: %s\n\n", verdict == kPass ? "yes" : verdict == kFail ? "NO" : "inconclusive", what);
    return verdict;
}

/*
 * The options on the active pam_tidcmd line in sudo_local, or nil if there is
 * none. OpenPAM ends a line at the first #, even inside a word.
 */
static NSArray<NSString *> *module_options(void) {
    NSString *conf = [NSString stringWithContentsOfFile:@"/etc/pam.d/sudo_local" encoding:NSUTF8StringEncoding error:NULL];
    NSPredicate *nonEmpty = [NSPredicate predicateWithFormat:@"length > 0"];
    for (NSString *line in [conf componentsSeparatedByString:@"\n"]) {
        NSString *active = [line componentsSeparatedByString:@"#"].firstObject;
        NSArray<NSString *> *fields = [[active componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]
            filteredArrayUsingPredicate:nonEmpty];
        if (fields.count >= 3 && [fields[0] isEqualToString:@"auth"] &&
            ([fields[2] isEqualToString:@"pam_tidcmd.so"] || [fields[2] hasSuffix:@"/pam_tidcmd.so"])) {
            return [fields subarrayWithRange:NSMakeRange(3, fields.count - 3)];
        }
    }
    return nil;
}

/* The timeout the module reads from those options. */
static unsigned configured_timeout(NSArray<NSString *> *options) {
    const char *argv[options.count + 1];
    for (NSUInteger i = 0; i < options.count; i++) argv[i] = options[i].UTF8String;
    argv[options.count] = NULL;
    return tidcmd_timeout((int)options.count, argv);
}

/* Prints the verdict for one pair of measurements. */
static int verdict(const char *what, CGFloat shortText, CGFloat longText) {
    if (shortText == 0 || longText == 0) {
        printf("  -> inconclusive: %s\n\n", what);
        return kInconclusive;
    }
    BOOL grew = longText > shortText;
    printf("  -> %s: %s\n\n", grew ? "yes" : "NO", what);
    return grew ? kPass : kFail;
}

static int worse(int a, int b) {
    return (a == kFail || b == kFail) ? kFail : (a == kInconclusive || b == kInconclusive) ? kInconclusive : kPass;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc >= 2 && strcmp(argv[1], "--request") == 0) {
            return request_right(argc >= 3 ? argv[2] : NULL);
        }
        if (argc >= 4 && strcmp(argv[1], "--authorize") == 0) {
            return authorize_like_module(argv[2], argv[3]);
        }

        char self[PATH_MAX];
        uint32_t size = sizeof self;
        if (_NSGetExecutablePath(self, &size) != 0) return 2;

        struct sigaction sa = {0};
        sa.sa_handler = interrupted;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);

        printf("Raising authorization dialogs and closing them again. Do not answer them.\n\n");
        int result = kPass;

        printf("Unprivileged right (Apple's default rule):\n");
        CGFloat plain = dialog_height(@"no prompt", (char *[]){self, "--request", NULL});
        CGFloat prompted = plain == kCleanupFailed || stopSignal ? kCleanupFailed : dialog_height(@"six-line prompt",
            (char *[]){self, "--request", "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6", NULL});
        purge_shared_credential();
        if (stopSignal) return 128 + stopSignal;
        if (plain == kCleanupFailed || prompted == kCleanupFailed) {
            printf("  -> stopped\n");
            return kStopped;
        }
        result = worse(result, verdict("the dialog shows a prompt from the request", plain, prompted));

        char option[32];
        snprintf(option, sizeof option, "timeout=%u", kProbeTimeout);
        printf("The same right, asked for the way the module asks (%s):\n", option);
        int closed = closes_by_itself([NSString stringWithUTF8String:option],
            (char *[]){self, "--authorize", option, "This dialog closes by itself.", NULL},
            kProbeTimeout, 0, "the dialog closes when the timeout runs out");
        purge_shared_credential();
        if (stopSignal) return 128 + stopSignal;
        if (closed == kStopped) {
            printf("  -> stopped\n");
            return kStopped;
        }
        result = worse(result, closed);

        printf("sudo with pam_tidcmd:\n");
        NSArray<NSString *> *options = module_options();
        if (!options) {
            printf("  -> skipped: pam_tidcmd is not active in /etc/pam.d/sudo_local\n");
            return result;
        }
        CGFloat shortCommand = dialog_height(@"sudo -k /usr/bin/true",
            (char *[]){"/usr/bin/sudo", "-k", "/usr/bin/true", NULL});
        char *longArgv[44] = {"/usr/bin/sudo", "-k", "/usr/bin/true"};
        for (int i = 0; i < 40; i++) longArgv[3 + i] = "padding";
        longArgv[43] = NULL;
        CGFloat longCommand = shortCommand == kCleanupFailed || stopSignal ? kCleanupFailed :
            dialog_height(@"... plus 40 arguments", longArgv);
        if (stopSignal) return 128 + stopSignal;
        if (shortCommand == kCleanupFailed || longCommand == kCleanupFailed) {
            printf("  -> stopped\n");
            return kStopped;
        }
        result = worse(result, verdict("sudo's dialog shows the command line", shortCommand, longCommand));

        unsigned timeout = configured_timeout(options);
        if (timeout == 0 || timeout > kMaxSudoTimeout) {
            printf(timeout == 0 ? "  -> skipped: timeout=0, so sudo's dialog has no timeout\n" :
                "  -> skipped: the timeout is %u s; this check waits for at most %u s\n", timeout, kMaxSudoTimeout);
            return result;
        }
        printf("  (leave the next dialog alone for %u s)\n", timeout);
        closed = closes_by_itself(@"sudo -k /usr/bin/true", (char *[]){"/usr/bin/sudo", "-k", "/usr/bin/true", NULL},
            timeout, 1, "sudo's dialog closes when the timeout runs out");
        if (stopSignal) return 128 + stopSignal;
        if (closed == kStopped) {
            printf("  -> stopped\n");
            return kStopped;
        }
        return worse(result, closed);
    }
}
