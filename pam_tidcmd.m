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
    kMaxAncestors = 5,
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
 * Make a string safe to show in the dialog: anything that is not a plainly
 * visible character (control characters, newlines, bidi overrides, zero-width
 * and other format characters, unusual spaces) is written as \u{XXXX} so it
 * cannot rearrange or hide the rest of the text. Sets *changed if it did so.
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
        BOOL ok = (c >= 0x20 && c <= 0x7e) || (c > 0x7f && [allowed longCharacterIsMember:c]);
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

/* One argument as it should appear on the displayed command line. */
static NSString *quoted_arg(const char *arg) {
    static NSCharacterSet *needsQuoting;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needsQuoting = [[NSCharacterSet characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"] invertedSet];
    });

    BOOL changed = NO;
    NSString *s = visible(string_from_bytes(arg, &changed), &changed);
    if (s.length > 0 && !changed && [s rangeOfCharacterFromSet:needsQuoting].location == NSNotFound) {
        return s;
    }
    s = [s stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
    return [NSString stringWithFormat:@"'%@'", s];
}

static NSString *command_line(int argc, char **argv) {
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithCapacity:(NSUInteger)argc];
    for (int i = 0; i < argc && argv[i]; i++) {
        [parts addObject:quoted_arg(argv[i])];
    }
    NSString *line = [parts componentsJoinedByString:@" "];
    if (line.length <= kMaxCommandLength) return line;

    /* Cut on composed-character boundaries so no surrogate pair is split. */
    NSRange head = [line rangeOfComposedCharacterSequencesForRange:NSMakeRange(0, kCommandHead)];
    NSRange tail = [line rangeOfComposedCharacterSequencesForRange:
        NSMakeRange(line.length - kCommandTail, kCommandTail)];
    NSUInteger omitted = tail.location - NSMaxRange(head);
    return [NSString stringWithFormat:@"%@ …[%lu CHARACTERS NOT SHOWN]… %@",
        [line substringWithRange:head], (unsigned long)omitted, [line substringWithRange:tail]];
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

NSString *tidcmd_build_prompt(int argc, char **argv, const char *home) {
    return [NSString stringWithFormat:@"Command: %@\nDirectory: %@\nRequested by: %@\n\n",
        command_line(argc, argv), working_directory(home), requesting_processes()];
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

EXPORT PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    @autoreleasepool {
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

        /* sudo -A: the askpass program is expected to do the asking. */
        const void *askpass = NULL;
        if (pam_get_data(pamh, "askpass-enabled", &askpass) == PAM_SUCCESS) {
            return PAM_AUTHINFO_UNAVAIL;
        }

        if (!tidcmd_touchid_usable(pwd->pw_uid)) {
            return PAM_AUTH_ERR;
        }

        const char *prompt = tidcmd_build_prompt(*_NSGetArgc(), *_NSGetArgv(), pwd->pw_dir).UTF8String;

        AuthorizationRef authorization = NULL;
        OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
        if (status != errAuthorizationSuccess) {
            os_log_error(tidcmd_log(), "AuthorizationCreate failed: %d", (int)status);
            return PAM_AUTH_ERR;
        }

        AuthorizationItem right = {"com.apple.security.sudo", 0, NULL, 0};
        AuthorizationRights rights = {1, &right};
        AuthorizationItem promptItem = {kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0};
        AuthorizationEnvironment environment = {1, &promptItem};
        AuthorizationRights *granted = NULL;
        status = AuthorizationCopyRights(authorization, &rights, &environment,
            kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights,
            &granted);
        if (granted) AuthorizationFreeItemSet(granted);
        AuthorizationFree(authorization, kAuthorizationFlagDefaults);

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
