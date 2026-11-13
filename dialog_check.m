/*
 * dialog_check: shows whether the prompt text reaches the authorization dialog.
 *
 * The dialog's text cannot be read without Screen Recording or Accessibility
 * permission, but its size can, and the dialog grows with the text it shows.
 * So each check raises the dialog twice, with a short and a long text, and
 * compares the heights:
 *
 *   right  An undefined right (Apple's "default" rule), requested by this
 *          program with no prompt and then with a six-line prompt.
 *   sudo   The installed module: `sudo -k /usr/bin/true`, then the same with
 *          40 extra arguments. Only the module's prompt depends on argv.
 *
 * Each dialog is left open for about two seconds and then withdrawn by killing
 * the process that asked for it; authd then closes the dialog. Ctrl-C stops
 * the check and withdraws the open dialog the same way. There is no need to
 * approve anything. If a dialog is approved anyway, sudo runs `/usr/bin/true`
 * as root, or the default rule leaves an admin credential that the session
 * shares for five minutes. The program destroys that credential: see
 * purge_shared_credential(). Only killing this program with SIGKILL skips
 * the cleanup.
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

static const char *kProbeRight = "com.github.pam-tidcmd.dialog-check";

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

/* Waits up to the given time for the child to end. */
static BOOL reaped(pid_t pid, int tenths) {
    for (int tick = 0; tick <= tenths; tick++) {
        pid_t r = waitpid(pid, NULL, WNOHANG);
        if (r == pid || (r == -1 && errno == ECHILD)) return YES;
        if (tick < tenths) usleep(100 * 1000);
    }
    return NO;
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
            for (NSNumber *key in now) {
                if (![before containsObject:key]) windowID = key;
            }
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

    if (!exited) {
        /* If someone answered the dialog, let the child finish, so it can destroy what it was granted. */
        if (!(closed && reaped(pid, 30))) {
            /* SIGKILL, because sudo catches SIGINT and SIGTERM until authentication is over. */
            kill(pid, SIGKILL);
            if (!reaped(pid, 50)) {
                printf("  %-24s could not end process %d; end it, then cancel its dialog\n", label.UTF8String, pid);
                return kCleanupFailed;
            }
        }
    }
    BOOL lingering = NO;
    for (int tick = 0; tick < 30 && (lingering = windowID && agent_windows()[windowID]); tick++) usleep(100 * 1000);
    if (lingering) {
        printf("  %-24s the dialog is still open; cancel it\n", label.UTF8String);
        return kCleanupFailed;
    }

    if (steady < 5) {
        printf("  %-24s %s\n", label.UTF8String,
            closed ? "the dialog closed before it could be measured" :
            exited ? "no dialog appeared (the process ended on its own)" : "no dialog appeared");
        return 0;
    }
    printf("  %-24s dialog %.0f x %.0f\n", label.UTF8String, last.size.width, last.size.height);
    return last.size.height;
}

static BOOL module_configured(void) {
    NSString *conf = [NSString stringWithContentsOfFile:@"/etc/pam.d/sudo_local" encoding:NSUTF8StringEncoding error:NULL];
    for (NSString *line in [conf componentsSeparatedByString:@"\n"]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([trimmed hasPrefix:@"auth"] && [trimmed containsString:@"pam_tidcmd.so"]) return YES;
    }
    return NO;
}

enum { kPass = 0, kFail = 1, kInconclusive = 2, kStopped = 3 };

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

        char self[PATH_MAX];
        uint32_t size = sizeof self;
        if (_NSGetExecutablePath(self, &size) != 0) return 2;

        struct sigaction sa = {0};
        sa.sa_handler = interrupted;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);

        printf("Raising authorization dialogs and closing them again. Do not approve them.\n\n");
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

        printf("sudo with pam_tidcmd:\n");
        if (!module_configured()) {
            printf("  -> skipped: pam_tidcmd is not active in /etc/pam.d/sudo_local\n");
        } else {
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
        }
        return result;
    }
}
