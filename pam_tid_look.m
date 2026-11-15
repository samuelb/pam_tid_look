/*
 * pam_tid_look: Touch ID for sudo, with the command shown in the dialog.
 *
 * Copyright (c) 2026 Samuel Barabas. MIT License, see LICENSE. Code taken
 * from macos-sudo-touchid-context by Lauri Gates is marked where it is.
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
#import <dirent.h>
#import <dlfcn.h>
#import <errno.h>
#import <libproc.h>
#import <objc/message.h>
#import <os/log.h>
#import <pwd.h>
#import <sys/acl.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unicode/uchar.h>

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

/* ICU's script codes (UScriptCode), which are stable. uscript.h is not in the SDK. */
enum {
    kScriptArmenian = 3,
    kScriptCherokee = 6,
    kScriptCyrillic = 8,
    kScriptGreek = 14,
    kScriptLatin = 25,
};

enum {
    kDefaultTimeout = 30, /* seconds the dialog waits for an answer */
    kMaxTimeout = 3600,
    kDismissRetry = 1,    /* seconds between dismissals while the request is still pending */
};

static os_log_t tid_look_log(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("pam_tid_look", "auth");
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

static int script_of(uint32_t c) {
    return u_getIntPropertyValue((UChar32)c, UCHAR_SCRIPT);
}

/* Scripts with letters that look like Latin ones. */
static BOOL latin_lookalike_script(int script) {
    return script == kScriptCyrillic || script == kScriptGreek ||
        script == kScriptArmenian || script == kScriptCherokee;
}

/* Whether NFKC changes the code point on its own. */
static BOOL changed_by_nfkc(uint32_t c) {
    uint32_t le = OSSwapHostToLittleInt32(c);
    NSString *s = [[NSString alloc] initWithBytes:&le length:sizeof le encoding:NSUTF32LittleEndianStringEncoding];
    return s && ![s.precomposedStringWithCompatibilityMapping isEqualToString:s];
}

/*
 * Marks the code points that are drawn but look like others, so that
 * /usr/bin/іd with a Cyrillic і does not pass for /usr/bin/id:
 *
 * - within a run of letters (marks included, so that a combining mark does
 *   not end the run), the Cyrillic, Greek, Armenian and Cherokee ones if the
 *   run also has a Latin letter;
 * - every letter, mark or number that NFKC changes (fullwidth ｉ, math bold
 *   𝐢, the ligature ﬁ, the Kelvin sign, Roman numeral ⅰ).
 *
 * A run entirely in one script passes: Cyrillic сс for cc is not caught.
 */
static void mark_lookalikes(const uint32_t *cp, NSUInteger count, BOOL *escape) {
    static NSCharacterSet *letters, *alphanumerics;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        letters = [NSCharacterSet letterCharacterSet];          /* L* and M* */
        alphanumerics = [NSCharacterSet alphanumericCharacterSet]; /* L*, M* and N* */
    });

    for (NSUInteger start = 0, end; start < count; start = end) {
        BOOL latin = NO, other = NO;
        for (end = start; end < count && [letters longCharacterIsMember:cp[end]]; end++) {
            int script = script_of(cp[end]);
            latin = latin || script == kScriptLatin;
            other = other || latin_lookalike_script(script);
        }
        if (latin && other) {
            for (NSUInteger i = start; i < end; i++) {
                if (latin_lookalike_script(script_of(cp[i]))) escape[i] = YES;
            }
        }
        if (end == start) end++;
    }
    for (NSUInteger i = 0; i < count; i++) {
        if (cp[i] > 0x7f && [alphanumerics longCharacterIsMember:cp[i]] && changed_by_nfkc(cp[i])) {
            escape[i] = YES;
        }
    }
}

/*
 * Make a string safe to show in the dialog: anything that is not a plainly
 * visible character (control characters, newlines, bidi overrides, zero-width
 * and other format characters, invisible letters and marks, unusual spaces)
 * or that looks like another character (see mark_lookalikes) is written as
 * \u{XXXX}, so it cannot rearrange, hide or pass for the rest of the text.
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
    NSUInteger count = utf32.length / sizeof(uint32_t);
    NSMutableData *host = [NSMutableData dataWithLength:count * sizeof(uint32_t)];
    NSMutableData *lookalike = [NSMutableData dataWithLength:count * sizeof(BOOL)];
    uint32_t *cp = host.mutableBytes;
    for (NSUInteger i = 0; i < count; i++) cp[i] = OSSwapLittleToHostInt32(((const uint32_t *)utf32.bytes)[i]);
    BOOL *escape = lookalike.mutableBytes;
    mark_lookalikes(cp, count, escape);

    NSMutableString *out = [NSMutableString stringWithCapacity:s.length];
    for (NSUInteger i = 0; i < count; i++) {
        uint32_t c = cp[i];
        BOOL ok = !escape[i] && ((c >= 0x20 && c <= 0x7e) ||
            (c > 0x7f && !draws_nothing(c) && [allowed longCharacterIsMember:c]));
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

/* A path made visible, with the user's home abbreviated to ~. */
static NSString *visible_path(const char *path, const char *home) {
    NSString *shown = visible(string_from_bytes(path, NULL), NULL);
    NSString *homeDir = home ? visible(string_from_bytes(home, NULL), NULL) : nil;
    if (homeDir.length > 1) {
        if ([shown isEqualToString:homeDir]) return @"~";
        if ([shown hasPrefix:[homeDir stringByAppendingString:@"/"]]) {
            return [@"~" stringByAppendingString:[shown substringFromIndex:homeDir.length]];
        }
    }
    return shown;
}

static NSString *working_directory(const char *home) {
    char buf[PATH_MAX];
    return getcwd(buf, sizeof buf) ? visible_path(buf, home) : @"(unknown)";
}

/*
 * The PATH hint. For a command word without a "/", sudo runs the first match
 * in the caller's PATH, which the command line does not show:
 * `PATH=~/evil:/usr/bin sudo id` reads "sudo id" and runs ~/evil/id. The hint
 * names that file. It is left out whenever finding the command or its file
 * is not clear-cut. See "The PATH hint" in DESIGN.md.
 */

/*
 * sudo's short options, from parse_args() in sudo 1.9.17p2 as Apple ships it.
 * A letter followed by ':' takes a value, by "::" an optional one.
 */
static const char kSudoOptions[] = "Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv";

/*
 * The options after which sudo still runs, as root, the file its PATH search
 * found. Every other one leaves the hint out: -s and -i (a shell finds the
 * command), -e (sudoedit), -l, -v, -K, -V and -h (nothing runs), -D and -R
 * (another directory or root), -g and -U (another user), and -a, -c, -r and
 * -t (BSD authentication, login classes and SELinux, not used on macOS).
 * -u stays only with root.
 */
static const char kHintOptions[] = "ABbCEHkNnPpSTu";

/* Whether sudo's -u value is root: the name, or "#" and a uid of zeros. */
static BOOL names_root(const char *user) {
    if (strcmp(user, "root") == 0) return YES;
    return user[0] == '#' && user[1] && strspn(user + 1, "0") == strlen(user + 1);
}

/*
 * The index in sudo's argv of the command word, or -1 when that is not
 * clear-cut. Mirrors only as much of parse_args() as finding it needs:
 * options end at "--" or at the first word that is not one, short flags
 * group, and a value is the rest of the word or the next word (-Eu root,
 * -uroot). VAR=value words between them are skipped, unless the word before
 * is "--" (got_end_of_args). Long options leave the hint out, because
 * getopt_long accepts abbreviations, and so do the letters kHintOptions
 * leaves out, and sudoedit.
 */
static int command_index(int argc, char **argv) {
    /* parse_args() edits when sudo's program name ends in "edit". */
    const char *name = getprogname();
    size_t nameLength = name ? strlen(name) : 0;
    if (nameLength > 4 && strcmp(name + nameLength - 4, "edit") == 0) return -1;

    BOOL user = NO;
    int i = 1;
    while (i < argc && argv[i]) {
        const char *word = argv[i];
        if (strcmp(word, "--") == 0) {
            i++;
            break;
        }
        if (word[0] == '-' && word[1] == '-') return -1;
        if (word[0] == '-' && word[1]) {
            i++;
            for (const char *c = word + 1; *c; c++) {
                const char *spec = *c == ':' ? NULL : strchr(kSudoOptions, *c);
                if (!spec || !strchr(kHintOptions, *c)) return -1;
                if (spec[1] != ':') continue;
                const char *value = c[1] ? c + 1 : i < argc ? argv[i++] : NULL;
                if (!value) return -1;
                if (*c == 'u') {
                    if (user || !names_root(value)) return -1;
                    user = YES;
                }
                break;
            }
            continue;
        }
        BOOL endOfOptions = i > 1 && strcmp(argv[i - 1], "--") == 0;
        if (!endOfOptions && word[0] != '/' && strchr(word, '=')) {
            /* "=x" may not count as a variable; PATH=x may change the search. */
            if (word[0] == '=' || strncmp(word, "PATH=", 5) == 0) return -1;
            i++;
            continue;
        }
        break;
    }
    return i < argc && argv[i] ? i : -1;
}

/*
 * The PATH sudoers searches: the last non-empty PATH= in the environment
 * exec passed (init_vars() in plugins/sudoers/sudoers.c), not the first,
 * which getenv() would return.
 */
static const char *sudoers_path(char **envp) {
    const char *path = NULL;
    for (char **e = envp; e && *e; e++) {
        if (strncmp(*e, "PATH=", 5) == 0 && (*e)[5]) path = *e + 5;
    }
    return path;
}

/*
 * Whether path itself (a symbolic link is not followed) has an ACL entry that
 * match() accepts. An ACL or an entry that cannot be read counts as one.
 */
static BOOL acl_has(const char *path, BOOL (*match)(acl_entry_t entry, acl_tag_t tag)) {
    acl_t acl = acl_get_link_np(path, ACL_TYPE_EXTENDED);
    if (!acl) return errno != ENOENT; /* ENOENT: no ACL */
    BOOL found = NO;
    acl_entry_t entry;
    for (int which = ACL_FIRST_ENTRY; !found && acl_get_entry(acl, which, &entry) == 0; which = ACL_NEXT_ENTRY) {
        acl_tag_t tag;
        found = acl_get_tag_type(entry, &tag) != 0 || match(entry, tag);
    }
    acl_free(acl);
    return found;
}

/* An entry that allows something, which may let someone other than the owner change the file. */
static BOOL allows(acl_entry_t entry, acl_tag_t tag) {
    return tag == ACL_EXTENDED_ALLOW;
}

/* An entry that denies searching a directory, to anyone. */
static BOOL denies_search(acl_entry_t entry, acl_tag_t tag) {
    acl_permset_t perms;
    return tag == ACL_EXTENDED_DENY && (acl_get_permset(entry, &perms) != 0 || acl_get_perm_np(perms, ACL_SEARCH) != 0);
}

/* A test walk() applies to each component of a path: the component, its lstat() and the test's context. */
typedef BOOL (*walk_test)(const char *path, const struct stat *st, const void *context);

typedef enum { kWalkPassed, kWalkFailed, kWalkMissing } walk_result;

/*
 * Walks an absolute path as the kernel resolves it: "/", then each component
 * in turn, following symbolic links (whose targets are walked too), and
 * applies passes() to every one of them. kWalkPassed when all pass;
 * kWalkMissing when a component does not exist (ENOENT, or ENOTDIR under a
 * file) and every one before it passed; kWalkFailed when one does not pass
 * or anything else goes wrong (too long, a loop, an unreadable link).
 */
static walk_result walk(const char *path, walk_test passes, const void *context) {
    char at[PATH_MAX] = "/";  /* absolute, without symbolic links, and checked */
    char rest[2 * PATH_MAX];  /* what is left to walk */
    struct stat st;
    if (lstat("/", &st) != 0 || !passes("/", &st, context) || strlcpy(rest, path, sizeof rest) >= sizeof rest) {
        return kWalkFailed;
    }
    for (int links = 0; rest[0]; ) {
        size_t length = strcspn(rest, "/");
        char part[PATH_MAX];
        if (length >= sizeof part) return kWalkFailed;
        memcpy(part, rest, length);
        part[length] = '\0';
        size_t taken = length + (rest[length] == '/');
        memmove(rest, rest + taken, strlen(rest + taken) + 1);
        if (!part[0] || strcmp(part, ".") == 0) continue;
        if (strcmp(part, "..") == 0) {
            char *slash = strrchr(at, '/');
            if (slash == at) at[1] = '\0'; /* the parent of "/x" and of "/" is "/" */
            else *slash = '\0';
            continue;
        }
        char next[PATH_MAX];
        if (snprintf(next, sizeof next, "%s/%s", strcmp(at, "/") ? at : "", part) >= (int)sizeof next) {
            return kWalkFailed;
        }
        if (lstat(next, &st) != 0) return errno == ENOENT || errno == ENOTDIR ? kWalkMissing : kWalkFailed;
        if (!passes(next, &st, context)) return kWalkFailed;
        if (!S_ISLNK(st.st_mode)) {
            strlcpy(at, next, sizeof at);
            continue;
        }
        char target[PATH_MAX], joined[sizeof rest];
        ssize_t n = readlink(next, target, sizeof target - 1);
        if (n <= 0 || ++links > 32) return kWalkFailed;
        target[n] = '\0';
        if (target[0] == '/') strlcpy(at, "/", sizeof at);
        if (snprintf(joined, sizeof joined, "%s/%s", target, rest) >= (int)sizeof joined) return kWalkFailed;
        strlcpy(rest, joined, sizeof rest);
    }
    return kWalkPassed;
}

/* Whether only root can change path itself: owned by root, not group or world writable, no allowing ACL. */
static BOOL root_owned(const char *path, const struct stat *st, const void *context) {
    return st->st_uid == 0 && !(st->st_mode & (S_IWGRP | S_IWOTH)) && !acl_has(path, allows);
}

/*
 * Whether only root can change what an absolute path names: "/", every
 * directory on the way and the file itself, through symbolic links, pass
 * root_owned(). The rule of check_dirs() in pam_tid_look.sh. Anything that
 * cannot be checked fails, a missing component too.
 */
static BOOL root_only(const char *path) {
    return walk(path, root_owned, NULL) == kWalkPassed;
}

/* The account sudo authenticates: who the PATH search must not see past. */
typedef struct {
    uid_t uid;
    gid_t gid; /* the primary group only */
} account_ids;

/*
 * Whether the account can search path, if it is a directory: the execute bit
 * of the owner if the account owns it, else of the group if that is the
 * account's primary group, else of both the group and others, since the
 * account may be in the directory's group as a supplementary one and the
 * group's bits then apply instead of the others'. And no ACL entry that
 * denies searching. Following a symbolic link, or looking up a name in a
 * file, needs no permission.
 */
static BOOL searchable(const char *path, const struct stat *st, const void *context) {
    const account_ids *account = context;
    if (!S_ISDIR(st->st_mode)) return YES;
    mode_t bits = st->st_uid == account->uid ? S_IXUSR : st->st_gid == account->gid ? S_IXGRP : S_IXGRP | S_IXOTH;
    return (st->st_mode & bits) == bits && !acl_has(path, denies_search);
}

/*
 * The file sudoers' find_path() picks for word, searching path as root, or
 * NULL when that is not clear-cut. Each entry is tried as "entry/word", and
 * the first regular file with an execute bit wins. sudo tries empty and "."
 * entries only after all the others, so a match that only they could give
 * leaves the hint out, as do a relative entry, a candidate too long for
 * sudo and an error other than "no such file".
 *
 * sudoers searches as the user the command runs as, then as the caller
 * (resolve_cmnd.c). For a command that runs as root, the first search is
 * this one. The module runs as root, but the prompt is shown before the
 * caller has authenticated, so the hint must tell the caller nothing about
 * files it could not see: each candidate is walked first, and every
 * directory on the way, through symbolic links, must be searchable() by the
 * account. If one is not, there is no hint at all, not just no match in that
 * entry: what a later entry gives would tell whether the earlier one has the
 * file, and it is not what sudo runs if it does. The result is malloc'd.
 */
static char *path_lookup(const char *word, const char *path, const account_ids *account) {
    for (const char *entry = path; ; ) {
        size_t length = strcspn(entry, ":");
        if (length > 0 && !(length == 1 && entry[0] == '.')) {
            if (entry[0] != '/') return NULL;
            char candidate[PATH_MAX];
            if (length >= sizeof candidate ||
                snprintf(candidate, sizeof candidate, "%.*s/%s", (int)length, entry, word) >= (int)sizeof candidate) {
                return NULL;
            }
            walk_result walked = walk(candidate, searchable, account);
            if (walked == kWalkFailed) return NULL;
            struct stat st;
            if (walked == kWalkPassed) {
                if (stat(candidate, &st) != 0) return NULL;
                if (S_ISREG(st.st_mode) && (st.st_mode & 0111)) return strdup(candidate);
            }
        }
        if (!entry[length]) return NULL;
        entry += length + 1;
    }
}

/*
 * The PATH section of the prompt, or "" when there is no hint. envp is the
 * environment as exec passed it, or NULL when that is unknown or sudo does not
 * search the caller's PATH (see tid_look_policy_uses_path). account is the
 * user sudo authenticates.
 *
 * The section warns when someone other than root can change the file found.
 * It does not look at the PATH directories before the match.
 */
static NSString *path_hint(int argc, char **argv, char **envp, const char *home, const account_ids *account) {
    int i = command_index(argc, argv);
    const char *path = sudoers_path(envp);
    if (i < 0 || !path || !argv[i][0] || strchr(argv[i], '/')) return @"";
    char *match = path_lookup(argv[i], path, account);
    if (!match) return @"";
    NSString *shown = cut_middle(visible_path(match, home), kMaxContextLength, kDirectoryHead, kDirectoryTail);
    BOOL safe = root_only(match);
    free(match);
    return [NSString stringWithFormat:@"Found in PATH:\n%@\n%@\n", shown, safe ? @"" : @"Can be changed without root.\n"];
}

/*
 * sudo's environment as exec passed it, duplicates kept, as a NULL-terminated
 * array in one allocation for free(). sudoers searched the PATH from there.
 *
 * It is read back from the process's own memory with KERN_PROCARGS2: argc,
 * the executable path, NUL padding, the argument strings, the environment
 * strings, then the kernel's "apple" strings (ptr_munge= and the like),
 * which are returned too: none of them is a PATH. The environment array that
 * sudo's main() got may have been changed since (dyld drops DYLD_ variables
 * from it for a setuid program, setenv() and unsetenv() change it); the
 * strings themselves stay where exec put them.
 *
 * NULL unless the arguments found there are sudo's argv, byte for byte and
 * back to back, so that the environment is known to start where they end.
 * That fails for an empty argv[0], which the padding hides, and for an
 * argument sudo cut in place (--preserve-env=A,B; see original_arg), except
 * the last one, which has no next one to measure against. Its pieces would
 * be read as environment strings; but sudo only cuts an option, an option is
 * last only when there is no command, and without one there is no hint.
 * Reading KERN_PROCARGS2 up to argv follows process_argv() in
 * https://github.com/laurigates/macos-sudo-touchid-context
 * (MIT License, Copyright (c) 2026 Lauri Gates).
 */
char **tid_look_exec_environment(void) {
    int argc = *_NSGetArgc();
    char **argv = *_NSGetArgv();
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, getpid()};
    size_t size = 0;
    int count;
    if (argc < 1 || !argv || sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size <= sizeof count) return NULL;
    char *buffer = malloc(size), **env = NULL;
    if (!buffer || sysctl(mib, 3, buffer, &size, NULL, 0) != 0 || size <= sizeof count) goto done;
    memcpy(&count, buffer, sizeof count);
    if (count != argc) goto done;

    const char *p = buffer + sizeof count, *end = buffer + size;
    p += strnlen(p, (size_t)(end - p));
    while (p < end && !*p) p++;
    for (int i = 0; i < argc; i++) {
        size_t length = strnlen(p, (size_t)(end - p));
        if (p + length == end || !argv[i] || strcmp(p, argv[i]) != 0) goto done;
        if (i + 1 < argc && (!argv[i + 1] || (uintptr_t)argv[i + 1] - (uintptr_t)argv[i] != length + 1)) goto done;
        p += length + 1;
    }

    size_t strings = 0, bytes = (size_t)(end - p);
    for (const char *q = p; q < end; q += strnlen(q, (size_t)(end - q)) + 1) {
        if (*q) strings++;
    }
    env = malloc((strings + 1) * sizeof *env + bytes + 1);
    if (!env) goto done;
    char *copy = (char *)(env + strings + 1);
    memcpy(copy, p, bytes);
    copy[bytes] = '\0';
    size_t k = 0;
    for (char *q = copy; q < copy + bytes; q += strlen(q) + 1) {
        if (*q) env[k++] = q;
    }
    env[k] = NULL;
done:
    free(buffer);
    return env;
}

/*
 * Adds to found each of words that the sudoers file file, or a file it
 * includes (#include, @include, #includedir, @includedir), mentions outside a
 * comment, in any case. NO when it cannot be sure: a file it cannot read, an
 * include it does not follow (anything but the directive, white space and one
 * path without %h, quotes or backslashes), or nesting more than 8 deep.
 * Looking for words rather than parsing sudoers errs one way only: a word
 * where it sets nothing still counts, and the hint is left out.
 */
static BOOL sudoers_mentions(NSString *file, NSArray<NSString *> *words, NSMutableSet<NSString *> *found, int depth) {
    if (depth > 8) return NO;
    NSData *data = [NSData dataWithContentsOfFile:file];
    if (!data) return NO;
    NSString *text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    NSCharacterSet *space = [NSCharacterSet whitespaceCharacterSet];
    NSMutableCharacterSet *unfollowed = [NSMutableCharacterSet characterSetWithCharactersInString:@"%\"\\"];
    [unfollowed formUnionWithCharacterSet:space];
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:space];
        NSString *directive = nil; /* longest first: "#include" is a prefix of "#includedir" */
        for (NSString *d in @[@"#includedir", @"@includedir", @"#include", @"@include"]) {
            if ([line hasPrefix:d]) {
                directive = d;
                break;
            }
        }
        if (directive) {
            NSString *rest = [line substringFromIndex:directive.length];
            NSString *arg = [rest stringByTrimmingCharactersInSet:space];
            if (!rest.length || ![space characterIsMember:[rest characterAtIndex:0]] || !arg.length ||
                [arg rangeOfCharacterFromSet:unfollowed].location != NSNotFound) {
                return NO;
            }
            NSString *target = [arg hasPrefix:@"/"] ? arg :
                [file.stringByDeletingLastPathComponent stringByAppendingPathComponent:arg];
            if (![directive hasSuffix:@"dir"]) {
                if (!sudoers_mentions(target, words, found, depth + 1)) return NO;
                continue;
            }
            DIR *dir = opendir(target.fileSystemRepresentation);
            if (!dir) return NO;
            BOOL ok = YES;
            for (struct dirent *e; ok && (e = readdir(dir));) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                NSString *name = [NSFileManager.defaultManager stringWithFileSystemRepresentation:e->d_name
                                                                                             length:strlen(e->d_name)];
                NSString *entry = [target stringByAppendingPathComponent:name];
                struct stat st;
                if (stat(entry.fileSystemRepresentation, &st) != 0) ok = NO;
                else if (S_ISREG(st.st_mode)) ok = sudoers_mentions(entry, words, found, depth + 1);
            }
            closedir(dir);
            if (!ok) return NO;
            continue;
        }
        if ([line hasPrefix:@"#"]) continue; /* a comment, or a "#uid" user, which sets no Defaults */
        for (NSString *w in words) {
            if ([line rangeOfString:w options:NSCaseInsensitiveSearch].location != NSNotFound) [found addObject:w];
        }
    }
    return YES;
}

/*
 * Whether sudo is known to search the caller's PATH, and to run a command
 * without -u as root: sudoConf (sudo.conf, which may be missing) names no
 * plugin, and sudoers and the files it includes mention neither secure_path,
 * which sudo would search instead, nor runas_default, which would run the
 * command as another user. Neither is set on macOS as it ships.
 */
BOOL tid_look_policy_uses_path(const char *sudoConf, const char *sudoers) {
    struct stat st;
    if (stat(sudoConf, &st) == 0) {
        NSData *data = [NSData dataWithContentsOfFile:@(sudoConf)];
        if (!data) return NO;
        NSString *text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        for (NSString *raw in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
            NSString *line = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if ([line rangeOfString:@"plugin" options:NSCaseInsensitiveSearch | NSAnchoredSearch].location != NSNotFound) {
                return NO;
            }
        }
    } else if (errno != ENOENT) {
        return NO;
    }
    NSMutableSet<NSString *> *found = [NSMutableSet set];
    NSString *path = [NSFileManager.defaultManager stringWithFileSystemRepresentation:sudoers length:strlen(sudoers)];
    return sudoers_mentions(path, @[@"secure_path", @"runas_default"], found, 0) && found.count == 0;
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
 *
 * argv and envp are sudo's, as exec laid them out; envp may be NULL (see
 * path_hint). uid and gid are the user sudo authenticates and its primary
 * group, and home its home directory.
 */
NSString *tid_look_build_prompt(int argc, char **argv, char **envp, const char *home, uid_t uid, gid_t gid) {
    account_ids account = {uid, gid};
    return [NSString stringWithFormat:@"Command:\n%@\n\n%@Directory:\n%@\n\nRequested by:\n%@\n\n",
        command_line(argc, argv),
        path_hint(argc, argv, envp, home, &account),
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
BOOL tid_look_touchid_usable(uid_t uid) {
    LAContext *context = [[LAContext alloc] init];
    SEL sel = NSSelectorFromString(@"evaluatePolicy:options:error:");
    if (![context respondsToSelector:sel]) {
        os_log_error(tid_look_log(), "LAContext lacks evaluatePolicy:options:error:");
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
    os_log_debug(tid_look_log(), "Touch ID not usable: %ld", (long)error.code);
    return NO;
}

/*
 * The dialog's timeout in seconds, from the module's options in the PAM
 * config: timeout=SECONDS, a whole number from 0 to 3600 (at most four
 * digits). 0 means no timeout. Without the option, or with an invalid value,
 * it is kDefaultTimeout. Unknown options are logged and ignored.
 */
unsigned tid_look_timeout(int argc, const char **argv) {
    static const char key[] = "timeout=";
    unsigned timeout = kDefaultTimeout;
    for (int i = 0; i < argc && argv[i]; i++) {
        if (strncmp(argv[i], key, strlen(key)) != 0) {
            os_log_error(tid_look_log(), "ignoring unknown option %{public}s", argv[i]);
            continue;
        }
        const char *value = argv[i] + strlen(key);
        size_t digits = strspn(value, "0123456789");
        if (digits == 0 || digits > 4 || value[digits] != '\0' || atoi(value) > kMaxTimeout) {
            os_log_error(tid_look_log(), "ignoring %{public}s: expected 0 to %d seconds", argv[i], kMaxTimeout);
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
OSStatus tid_look_authorize(const char *rightName, const char *prompt, unsigned timeout) {
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess) {
        os_log_error(tid_look_log(), "AuthorizationCreate failed: %d", (int)status);
        return status;
    }

    OSStatus (*dismiss)(void) = NULL;
    if (timeout > 0) {
        dismiss = (OSStatus (*)(void))dlsym(RTLD_DEFAULT, "AuthorizationDismiss");
        if (!dismiss) os_log_error(tid_look_log(), "AuthorizationDismiss is missing; the dialog has no timeout");
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
        os_log(tid_look_log(), "no answer after %u seconds; dismissing the dialog", timeout);
        for (BOOL first = YES; ; first = NO) {
            OSStatus dismissed = dismiss();
            if (dispatch_semaphore_wait(answered, dispatch_time(DISPATCH_TIME_NOW, kDismissRetry * NSEC_PER_SEC)) == 0) break;
            if (first) os_log_error(tid_look_log(), "the dialog did not close (%d); dismissing it again", (int)dismissed);
        }
    }
    AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    return result;
}

static int authenticate(pam_handle_t *pamh, int argc, const char **argv) {
    unsigned timeout = tid_look_timeout(argc, argv);

    /* The account sudo asks about, as PAM names it. */
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        os_log_error(tid_look_log(), "PAM gave no user name");
        return PAM_AUTHINFO_UNAVAIL;
    }
    struct passwd entry, *account = NULL;
    char storage[4096];
    if (getpwnam_r(user, &entry, storage, sizeof storage, &account) != 0 || !account) {
        os_log_error(tid_look_log(), "no account entry for the PAM user");
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
    if (account->pw_uid != session.ai_auid) {
        os_log(tid_look_log(), "user %d is not the session owner %d", (int)account->pw_uid, (int)session.ai_auid);
        return PAM_AUTH_ERR;
    }

    /* sudo -A: the askpass program is expected to do the asking. */
    const void *askpass = NULL;
    if (pam_get_data(pamh, "askpass-enabled", &askpass) == PAM_SUCCESS) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (!tid_look_touchid_usable(account->pw_uid)) {
        return PAM_AUTH_ERR;
    }

    /* Read here, as root, which can read sudoers. */
    char **env = tid_look_policy_uses_path("/etc/sudo.conf", "/etc/sudoers") ? tid_look_exec_environment() : NULL;
    const char *prompt = tid_look_build_prompt(*_NSGetArgc(), *_NSGetArgv(), env, account->pw_dir,
        account->pw_uid, account->pw_gid).UTF8String;
    free(env);
    OSStatus status = tid_look_authorize("com.apple.security.sudo", prompt, timeout);
    os_log_debug(tid_look_log(), "authorization result: %d", (int)status);
    return status == errAuthorizationSuccess ? PAM_SUCCESS : PAM_AUTH_ERR;
}

/*
 * An exception left to escape would end sudo for everyone who has to
 * authenticate, while root's sudo, which is not asked to, still starts. So it
 * is caught, and sudo asks for the password instead. Every exception that can
 * reach here is thrown before the request is sent (tid_look_authorize throws
 * none), so no request is left pending.
 */
EXPORT PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    @autoreleasepool {
        @try {
            return authenticate(pamh, argc, argv);
        } @catch (NSException *e) {
            os_log_error(tid_look_log(), "exception %{public}@: %@", e.name, e.reason);
        } @catch (id e) {
            os_log_error(tid_look_log(), "exception: %@", e);
        }
        return PAM_AUTHINFO_UNAVAIL;
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
