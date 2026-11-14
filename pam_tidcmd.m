/*
 * pam_tidcmd: Touch ID for sudo, with the command shown in the dialog.
 *
 * This follows the flow of Apple's pam_tid.so
 * (apple-oss-distributions/pam_modules, modules/pam_tid/pam_tid.c):
 * Authorization Services decides, for the right "com.apple.security.sudo",
 * whether the session owner authenticated. The one difference is that the
 * request carries a prompt describing what sudo was asked to run, taken from
 * the argv of the sudo process this module is loaded into.
 *
 * It only works inside /usr/bin/sudo: the right's rule requires the calling
 * process to hold Apple's sudo entitlement.
 */

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Authorization.h>
#import <Security/AuthorizationTags.h>
#import <bsm/audit.h>
#import <crt_externs.h>
#import <dlfcn.h>
#import <libproc.h>
#import <objc/message.h>
#import <os/log.h>
#import <pwd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#import <security/pam_appl.h>
#import <security/pam_modules.h>

#define EXPORT __attribute__((visibility("default")))

/* Values from Apple's LAPrivateDefines.h, as compiled into pam_tid.so.2. */
enum {
    kLAOptionNotInteractive = 1000,
    kLAOptionUserId = 1019,
};

/* AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS from bsm/audit_session.h */
#define SESSION_HAS_GRAPHIC_ACCESS 0x0010

enum {
    kMaxCommandLength = 400, /* longer command lines are cut in the middle */
    kCommandHead = 280,
    kCommandTail = 80,
    kMaxContextLength = 200, /* the same for the Directory and Requested by lines */
    kDirectoryHead = 80,     /* the deepest directories are the telling part */
    kDirectoryTail = 100,
    kRequesterHead = 120,    /* the nearest processes come first */
    kRequesterTail = 60,
    kMaxAncestors = 5,
};

enum {
    kDefaultTimeout = 30, /* seconds the dialog waits for an answer */
    kMaxTimeout = 3600,
    kDismissRetry = 1,    /* seconds between dismissals while the request is still pending */
};

static os_log_t tidcmd_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("pam_tidcmd", "auth");
    });
    return log;
}

/*
 * Unicode's Default_Ignorable_Code_Point set, plus U+2800 BRAILLE PATTERN
 * BLANK. These draw nothing, although some are classed as letters (Hangul
 * fillers), marks (variation selectors, combining grapheme joiner) or symbols.
 */
static BOOL draws_nothing(uint32_t c) {
    return c == 0x00AD || c == 0x034F || c == 0x061C || c == 0x115F || c == 0x1160 ||
        c == 0x17B4 || c == 0x17B5 || (c >= 0x180B && c <= 0x180F) ||
        (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E) ||
        (c >= 0x2060 && c <= 0x206F) || c == 0x2800 || c == 0x3164 ||
        (c >= 0xFE00 && c <= 0xFE0F) || c == 0xFEFF || c == 0xFFA0 ||
        (c >= 0xFFF0 && c <= 0xFFF8) || (c >= 0x1BCA0 && c <= 0x1BCA3) ||
        (c >= 0x1D173 && c <= 0x1D17A) || (c >= 0xE0000 && c <= 0xE0FFF);
}

/*
 * Make a string safe to show in the dialog: anything that is not a plainly
 * visible character (control characters, newlines, bidi overrides, zero-width
 * and other format characters, invisible letters and marks, unusual spaces) is
 * written as \u{XXXX} so it cannot rearrange or hide the rest of the text.
 * Sets *changed if it did so.
 */
static NSString *visible(NSString *s, BOOL *changed) {
    static NSCharacterSet *allowed;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableCharacterSet *set = [NSMutableCharacterSet alphanumericCharacterSet];
        [set formUnionWithCharacterSet:[NSCharacterSet punctuationCharacterSet]];
        [set formUnionWithCharacterSet:[NSCharacterSet symbolCharacterSet]];
        [set formIntersectionWithCharacterSet:[[NSCharacterSet controlCharacterSet] invertedSet]];
        allowed = [set copy];
    });

    NSData *utf32 = [s dataUsingEncoding:NSUTF32LittleEndianStringEncoding];
    const uint32_t *cp = utf32.bytes;
    NSUInteger count = utf32.length / sizeof(uint32_t);
    NSMutableString *out = [NSMutableString stringWithCapacity:s.length];
    for (NSUInteger i = 0; i < count; i++) {
        uint32_t c = OSSwapLittleToHostInt32(cp[i]);
        BOOL ok = (c >= 0x20 && c <= 0x7e) ||
            (c > 0x7f && !draws_nothing(c) && [allowed longCharacterIsMember:c]);
        if (ok) {
            uint32_t le = OSSwapHostToLittleInt32(c);
            NSString *piece = [[NSString alloc] initWithBytes:&le length:sizeof le encoding:NSUTF32LittleEndianStringEncoding];
            [out appendString:piece ?: @"?"];
        } else {
            [out appendFormat:@"\\u{%X}", c];
            if (changed) *changed = YES;
        }
    }
    return out;
}

/* A C string that may not be valid UTF-8: undecodable bytes become \xNN. */
static NSString *string_from_bytes(const char *bytes, BOOL *changed) {
    NSString *s = [NSString stringWithUTF8String:bytes];
    if (s) return s;
    NSMutableString *out = [NSMutableString string];
    for (const unsigned char *p = (const unsigned char *)bytes; *p; p++) {
        if (*p < 0x80) [out appendFormat:@"%c", *p];
        else [out appendFormat:@"\\x%02X", *p];
    }
    if (changed) *changed = YES;
    return out;
}

/*
 * One argument as exec passed it to sudo. sudo shortens some arguments in
 * place before PAM runs: it splits --preserve-env=A,B with strtok_r(), which
 * writes a NUL over each comma. exec stores the argument strings back to back,
 * so an argument still runs up to the start of the next one. Read up to there,
 * with those NULs turned back into commas. The last argument has no next one
 * to measure against and is read as it is.
 */
static NSString *original_arg(const char *arg, const char *next, BOOL *changed) {
    size_t len = strlen(arg);
    uintptr_t start = (uintptr_t)arg, end = (uintptr_t)next;
    if (next && end > start + len + 1 && end - start <= ARG_MAX && next[-1] == '\0') {
        NSMutableData *copy = [NSMutableData dataWithBytes:arg length:end - start];
        char *bytes = copy.mutableBytes;
        for (size_t i = len; i < end - start - 1; i++) {
            if (bytes[i] == '\0') bytes[i] = ',';
        }
        return string_from_bytes(bytes, changed);
    }
    return string_from_bytes(arg, changed);
}

/* One argument as it should appear on the displayed command line. */
static NSString *quoted_arg(const char *arg, const char *next) {
    static NSCharacterSet *needsQuoting;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needsQuoting = [[NSCharacterSet characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"] invertedSet];
    });

    BOOL changed = NO;
    NSString *s = visible(original_arg(arg, next, &changed), &changed);
    if (s.length > 0 && !changed && [s rangeOfCharacterFromSet:needsQuoting].location == NSNotFound) {
        return s;
    }
    s = [s stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
    return [NSString stringWithFormat:@"'%@'", s];
}

/* An index to cut a string at, moved back by one if it would split a surrogate pair. */
static NSUInteger cut_index(NSString *s, NSUInteger i) {
    if (i > 0 && i < s.length && CFStringIsSurrogateLowCharacter([s characterAtIndex:i]) &&
        CFStringIsSurrogateHighCharacter([s characterAtIndex:i - 1])) {
        return i - 1;
    }
    return i;
}

/*
 * A line longer than max keeps its first head and last tail characters, with
 * a marker in between. max must be more than head + tail.
 *
 * The cuts are at fixed positions. Widening them to whole composed character
 * sequences would let one long sequence (a letter followed by thousands of
 * combining marks) take the whole line. Only surrogate pairs are kept whole.
 */
static NSString *cut_middle(NSString *line, NSUInteger max, NSUInteger head, NSUInteger tail) {
    if (line.length <= max) return line;
    NSUInteger end = cut_index(line, head);
    NSUInteger start = cut_index(line, line.length - tail);
    return [NSString stringWithFormat:@"%@ …[%lu CHARACTERS NOT SHOWN]… %@",
        [line substringToIndex:end], (unsigned long)(start - end), [line substringFromIndex:start]];
}

/*
 * argv must be laid out as exec left it: see original_arg().
 *
 * argv[0] is not shown: the caller of sudo chooses it freely and sudo does not
 * act on it, so `exec -a echo sudo rm -rf /` would otherwise read "echo rm -rf /".
 *
 * Arguments are separated by U+200E LEFT-TO-RIGHT MARK as well as a space.
 * Without it, the quotes and space between two right-to-left arguments take
 * their direction, and `cp 'א' 'ב'` is drawn as `cp 'ב' 'א'`.
 */
static NSString *command_line(int argc, char **argv) {
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithObject:@"sudo"];
    for (int i = 1; i < argc && argv[i]; i++) {
        [parts addObject:quoted_arg(argv[i], i + 1 < argc ? argv[i + 1] : NULL)];
    }
    return cut_middle([parts componentsJoinedByString:@"‎ "],
        kMaxCommandLength, kCommandHead, kCommandTail);
}

static NSString *working_directory(const char *home) {
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof buf)) return @"(unknown)";
    NSString *cwd = visible(string_from_bytes(buf, NULL), NULL);
    NSString *homeDir = home ? visible(string_from_bytes(home, NULL), NULL) : nil;
    if (homeDir.length > 1) {
        if ([cwd isEqualToString:homeDir]) return @"~";
        if ([cwd hasPrefix:[homeDir stringByAppendingString:@"/"]]) {
            return [@"~" stringByAppendingString:[cwd substringFromIndex:homeDir.length]];
        }
    }
    return cwd;
}

/* Names of the processes that led to this sudo, nearest first. */
static NSString *requesting_processes(void) {
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    pid_t pid = getppid();
    for (int i = 0; i < kMaxAncestors && pid > 1; i++) {
        struct proc_bsdinfo info;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info) != (int)sizeof info) break;

        char path[PROC_PIDPATHINFO_MAXSIZE];
        NSString *name = nil;
        if (proc_pidpath(pid, path, sizeof path) > 0) {
            name = string_from_bytes(path, NULL).lastPathComponent;
        }
        if (name.length == 0) {
            info.pbi_name[sizeof info.pbi_name - 1] = '\0';
            name = string_from_bytes(info.pbi_name, NULL);
        }
        name = visible(name, NULL);
        if (name.length > 0 && ![names.lastObject isEqualToString:name]) {
            [names addObject:name];
        }
        pid = (pid_t)info.pbi_ppid;
    }
    return names.count ? [names componentsJoinedByString:@" ← "] : @"(unknown)";
}

/*
 * Each label has a line of its own, so that a long value starts at the left
 * edge and wraps under itself, and a blank line separates the sections.
 */
NSString *tidcmd_build_prompt(int argc, char **argv, const char *home) {
    return [NSString stringWithFormat:@"Command:\n%@\n\nDirectory:\n%@\n\nRequested by:\n%@\n\n",
        command_line(argc, argv),
        cut_middle(working_directory(home), kMaxContextLength, kDirectoryHead, kDirectoryTail),
        cut_middle(requesting_processes(), kMaxContextLength, kRequesterHead, kRequesterTail)];
}

/*
 * Whether Touch ID could authenticate this user right now, checked without
 * showing UI. Apple's module does the same so that sudo falls back to the
 * terminal password prompt (lid closed, no fingerprints, biometry locked out)
 * instead of raising a password dialog. The call is private API, so if it is
 * ever missing this reports "not usable" and sudo asks for the password.
 */
BOOL tidcmd_touchid_usable(uid_t uid) {
    LAContext *context = [[LAContext alloc] init];
    SEL sel = NSSelectorFromString(@"evaluatePolicy:options:error:");
    if (![context respondsToSelector:sel]) {
        os_log_error(tidcmd_log(), "LAContext lacks evaluatePolicy:options:error:");
        return NO;
    }
    NSDictionary *options = @{
        @(kLAOptionNotInteractive) : @1,
        @(kLAOptionUserId) : @((int)uid),
    };
    NSError *error = nil;
    typedef id (*EvaluateFn)(id, SEL, NSInteger, NSDictionary *, NSError **);
    id result = ((EvaluateFn)objc_msgSend)(context, sel,
        LAPolicyDeviceOwnerAuthenticationWithBiometrics, options, &error);
    if (result) return YES;
    /* "would need UI" means Touch ID is available; anything else means it is not. */
    if (error.code == LAErrorNotInteractive) return YES;
    os_log_debug(tidcmd_log(), "Touch ID not usable: %ld", (long)error.code);
    return NO;
}

/*
 * The dialog's timeout in seconds, from the module's options in the PAM
 * config: timeout=SECONDS, a whole number from 0 to 3600 (at most four
 * digits). 0 means no timeout. Without the option, or with an invalid value,
 * it is kDefaultTimeout. Unknown options are logged and ignored.
 */
unsigned tidcmd_timeout(int argc, const char **argv) {
    static const char key[] = "timeout=";
    unsigned timeout = kDefaultTimeout;
    for (int i = 0; i < argc && argv[i]; i++) {
        if (strncmp(argv[i], key, strlen(key)) != 0) {
            os_log_error(tidcmd_log(), "ignoring unknown option %{public}s", argv[i]);
            continue;
        }
        const char *value = argv[i] + strlen(key);
        size_t digits = strspn(value, "0123456789");
        if (digits == 0 || digits > 4 || value[digits] != '\0' || atoi(value) > kMaxTimeout) {
            os_log_error(tidcmd_log(), "ignoring %{public}s: expected 0 to %d seconds", argv[i], kMaxTimeout);
            continue;
        }
        timeout = (unsigned)atoi(value);
    }
    return timeout;
}

/*
 * Asks authd for the right, showing the prompt, and returns its answer. If
 * the dialog is still open after timeout seconds (0: no limit), it is
 * dismissed, which makes authd end the request. The answer still decides:
 * a fingerprint given just before the dismissal is still a success.
 *
 * authd ignores a dismissal that reaches it before the request's dialog
 * exists: connection_destroy_agents() acts only on a running engine, and
 * engine_authorize() clears the dismissed flag when it starts. So the
 * dismissal is repeated until the request has ended.
 *
 * AuthorizationDismiss() is private API (AuthorizationPriv.h). If it is ever
 * missing, the dialog waits for an answer without a time limit.
 */
OSStatus tidcmd_authorize(const char *rightName, const char *prompt, unsigned timeout) {
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess) {
        os_log_error(tidcmd_log(), "AuthorizationCreate failed: %d", (int)status);
        return status;
    }

    OSStatus (*dismiss)(void) = NULL;
    if (timeout > 0) {
        dismiss = (OSStatus (*)(void))dlsym(RTLD_DEFAULT, "AuthorizationDismiss");
        if (!dismiss) os_log_error(tidcmd_log(), "AuthorizationDismiss is missing; the dialog has no timeout");
    }

    AuthorizationItem right = {rightName, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    AuthorizationItem promptItem = {kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0};
    AuthorizationEnvironment environment = {1, &promptItem};
    dispatch_semaphore_t answered = dispatch_semaphore_create(0);
    __block OSStatus result = errAuthorizationInternal;
    /* The callback runs on a dispatch queue. Every path below waits for it. */
    AuthorizationCopyRightsAsync(authorization, &rights, &environment,
        kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights,
        ^(OSStatus err, AuthorizationRights *granted) {
            result = err;
            if (granted) AuthorizationFreeItemSet(granted);
            dispatch_semaphore_signal(answered);
        });

    dispatch_time_t deadline = dismiss ?
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout * NSEC_PER_SEC) : DISPATCH_TIME_FOREVER;
    if (dispatch_semaphore_wait(answered, deadline) != 0) {
        os_log(tidcmd_log(), "no answer after %u seconds; dismissing the dialog", timeout);
        for (BOOL first = YES; ; first = NO) {
            OSStatus dismissed = dismiss();
            if (dispatch_semaphore_wait(answered, dispatch_time(DISPATCH_TIME_NOW, kDismissRetry * NSEC_PER_SEC)) == 0) break;
            if (first) os_log_error(tidcmd_log(), "the dialog did not close (%d); dismissing it again", (int)dismissed);
        }
    }
    AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    return result;
}

EXPORT PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    @autoreleasepool {
        unsigned timeout = tidcmd_timeout(argc, argv);

        const char *user = NULL;
        struct passwd pwdbuf, *pwd = NULL;
        char pwdstore[4096];
        if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user ||
            getpwnam_r(user, &pwdbuf, pwdstore, sizeof pwdstore, &pwd) != 0 || !pwd) {
            os_log_error(tidcmd_log(), "unable to obtain the username");
            return PAM_AUTHINFO_UNAVAIL;
        }

        /* No dialog without a GUI session (ssh, launchd jobs). */
        auditinfo_addr_t session = {0};
        if (getaudit_addr(&session, sizeof session) != 0 ||
            !(session.ai_flags & SESSION_HAS_GRAPHIC_ACCESS)) {
            return PAM_AUTH_ERR;
        }

        /*
         * authd authenticates the owner of this audit session, so its answer
         * only vouches for that user. sudo can be asking about another one:
         * with targetpw or runaspw, or from a shell switched to another user.
         */
        if (pwd->pw_uid != session.ai_auid) {
            os_log(tidcmd_log(), "user %d is not the session owner %d", (int)pwd->pw_uid, (int)session.ai_auid);
            return PAM_AUTH_ERR;
        }

        /* sudo -A: the askpass program is expected to do the asking. */
        const void *askpass = NULL;
        if (pam_get_data(pamh, "askpass-enabled", &askpass) == PAM_SUCCESS) {
            return PAM_AUTHINFO_UNAVAIL;
        }

        if (!tidcmd_touchid_usable(pwd->pw_uid)) {
            return PAM_AUTH_ERR;
        }

        const char *prompt = tidcmd_build_prompt(*_NSGetArgc(), *_NSGetArgv(), pwd->pw_dir).UTF8String;
        OSStatus status = tidcmd_authorize("com.apple.security.sudo", prompt, timeout);
        os_log_debug(tidcmd_log(), "authorization result: %d", (int)status);
        return status == errAuthorizationSuccess ? PAM_SUCCESS : PAM_AUTH_ERR;
    }
}

EXPORT PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

EXPORT PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
