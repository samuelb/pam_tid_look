/* Checks the parts of pam_tid_look that can run outside sudo. No dialog. */

#import <Foundation/Foundation.h>
#import <bsm/audit.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <pwd.h>
#import <security/pam_appl.h>
#import <spawn.h>
#import <sys/wait.h>

NSString *tid_look_build_prompt(int argc, char **argv, char **envp, const char *home);
char **tid_look_exec_environment(void);
BOOL tid_look_policy_uses_path(const char *sudoConf, const char *sudoers);
BOOL tid_look_touchid_usable(uid_t uid);
unsigned tid_look_timeout(int argc, const char **argv);
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

static int failures;

static int no_conversation(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    return PAM_CONV_ERR;
}

/* The line after a label line, such as the command line after "Command:". */
static NSString *section(NSString *prompt, NSString *label) {
    NSArray<NSString *> *lines = [prompt componentsSeparatedByString:@"\n"];
    NSUInteger i = [lines indexOfObject:label];
    return i != NSNotFound && i + 1 < lines.count ? lines[i + 1] : @"(no such section)";
}

static NSString *command_of(NSString *prompt) {
    return section(prompt, @"Command:");
}

/* The lines of the PATH section after its label, joined by " | ", or "(none)". */
static NSString *hint_of(NSString *prompt) {
    NSArray<NSString *> *lines = [prompt componentsSeparatedByString:@"\n"];
    NSUInteger i = [lines indexOfObject:@"Found in PATH:"];
    if (i == NSNotFound) return @"(none)";
    NSMutableArray<NSString *> *values = [NSMutableArray array];
    for (i++; i < lines.count && lines[i].length; i++) [values addObject:lines[i]];
    return [values componentsJoinedByString:@" | "];
}

/* Compares the command line, ignoring the left-to-right marks between arguments. */
static void expect(NSString *label, NSString *prompt, NSString *wanted) {
    NSString *command = [command_of(prompt) stringByReplacingOccurrencesOfString:@"‎" withString:@""];
    BOOL ok = [command isEqualToString:wanted];
    if (!ok) failures++;
    printf("%s  %s\n      got:    %s\n", ok ? "ok  " : "FAIL", label.UTF8String, command.UTF8String);
    if (!ok) printf("      wanted: %s\n", wanted.UTF8String);
}

static void check(BOOL ok, NSString *label, NSString *detail) {
    if (!ok) failures++;
    printf("%s  %s\n      got:    %s\n", ok ? "ok  " : "FAIL", label.UTF8String, detail.UTF8String);
}

/* Copies the arguments into one block, back to back, as exec lays them out. Never freed. */
static char **exec_layout(int argc, char **argv) {
    size_t size = 0;
    for (int i = 0; i < argc; i++) size += strlen(argv[i]) + 1;
    char *area = malloc(size);
    char **out = calloc((size_t)argc + 1, sizeof *out);
    for (int i = 0; i < argc; i++) {
        out[i] = area;
        area = stpcpy(area, argv[i]) + 1;
    }
    return out;
}

/* A command line of the form `sudo echo <arg>` whose argument is given as raw bytes. */
static NSString *line_with_arg(NSData *arg, const char *home) {
    NSMutableData *bytes = [arg mutableCopy];
    [bytes appendBytes:"" length:1];
    return command_of(tid_look_build_prompt(3, exec_layout(3, (char *[]){"sudo", "echo", bytes.mutableBytes}), NULL, home));
}

/* The PATH section's lines, compared like expect() compares the command line. */
static void expect_hint(NSString *label, NSString *prompt, NSString *wanted) {
    NSString *hint = hint_of(prompt);
    BOOL ok = [hint isEqualToString:wanted];
    if (!ok) failures++;
    printf("%s  %s\n      got:    %s\n", ok ? "ok  " : "FAIL", label.UTF8String, hint.UTF8String);
    if (!ok) printf("      wanted: %s\n", wanted.UTF8String);
}

/* A C string that lives as long as the test. */
static char *keep(NSString *s) {
    return strdup(s.fileSystemRepresentation);
}

/* An executable file, as a stand-in for a command. */
static BOOL make_command(NSString *path, short mode) {
    return [NSFileManager.defaultManager createFileAtPath:path
        contents:[@"#!/bin/sh\n" dataUsingEncoding:NSUTF8StringEncoding] attributes:@{NSFilePosixPermissions: @(mode)}];
}

/* Runs this program again with exactly these arguments and environment strings, and returns what it prints. */
static NSString *run_self(char **argv, char **envp) {
    char path[PATH_MAX];
    uint32_t size = sizeof path;
    int fds[2];
    if (_NSGetExecutablePath(path, &size) != 0 || pipe(fds) != 0) return @"(cannot run)";
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    pid_t pid;
    int err = posix_spawn(&pid, path, &actions, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    NSMutableData *out = [NSMutableData data];
    char buf[4096];
    for (ssize_t n; (n = read(fds[0], buf, sizeof buf)) > 0;) [out appendBytes:buf length:(NSUInteger)n];
    close(fds[0]);
    if (err != 0) return @"(cannot run)";
    waitpid(pid, NULL, 0);
    return [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] ?: @"(not UTF-8)";
}

/*
 * The child side of run_self(): prints the environment the module reads, one
 * string a line. A comma in argv[2] is first cut in place, as sudo does with
 * --preserve-env=A,B.
 */
static int print_environment(char **argv) {
    char *comma = argv[2] ? strchr(argv[2], ',') : NULL;
    if (comma) *comma = '\0';
    char **env = tid_look_exec_environment();
    if (!env) printf("(none)\n");
    for (char **e = env; e && *e; e++) printf("%s\n", *e);
    free(env);
    return 0;
}

/* The environment strings a child printed whose names are in names, in order. */
static NSString *printed(NSString *output, NSArray<NSString *> *names) {
    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *line in [output componentsSeparatedByString:@"\n"]) {
        NSRange eq = [line rangeOfString:@"="];
        if ([line isEqualToString:@"(none)"] || (eq.location != NSNotFound && [names containsObject:[line substringToIndex:eq.location]])) {
            [kept addObject:line];
        }
    }
    return [kept componentsJoinedByString:@" "];
}

/* A file with the given text, in dir. */
static char *write_file(NSString *dir, NSString *name, NSString *text) {
    NSString *path = [dir stringByAppendingPathComponent:name];
    [text writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:NULL];
    return keep(path);
}

/* The timeout read from the given module options. */
static void expect_timeout(NSString *label, unsigned wanted, int argc, const char **argv) {
    unsigned got = tid_look_timeout(argc, argv);
    check(got == wanted, label, [NSString stringWithFormat:@"%u seconds (wanted %u)", got, wanted]);
}

#define ARGV(...) ((char *[]){__VA_ARGS__, NULL})
#define COUNT(...) ((int)(sizeof((char *[]){__VA_ARGS__}) / sizeof(char *)))
/* A prompt for sudo's argv, with sudo's environment env. */
#define PROMPT_ENV(env, ...) tid_look_build_prompt(COUNT(__VA_ARGS__), exec_layout(COUNT(__VA_ARGS__), ARGV(__VA_ARGS__)), env, home)
/* The same with a PATH of the system's directories only, which only root can change. */
#define PROMPT(...) PROMPT_ENV(systemPath, __VA_ARGS__)

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc >= 2 && strcmp(argv[1], "--print-environment") == 0) return print_environment(argv);

        const char *home = getpwuid(getuid())->pw_dir;
        char **systemPath = ARGV("PATH=/usr/bin:/bin");

        expect(@"plain command", PROMPT("sudo", "brew", "services", "restart", "nginx"),
            @"sudo brew services restart nginx");
        expect(@"sudo flags are kept", PROMPT("sudo", "-u", "postgres", "-E", "psql"),
            @"sudo -u postgres -E psql");
        expect(@"spaces and quotes", PROMPT("sudo", "sh", "-c", "echo 'hi there' > /etc/x"),
            @"sudo sh -c 'echo '\\''hi there'\\'' > /etc/x'");
        expect(@"empty argument", PROMPT("sudo", "touch", ""), @"sudo touch ''");
        expect(@"newline cannot start a fake line", PROMPT("sudo", "true", "a\nCommand: ls"),
            @"sudo true 'a\\u{A}Command: ls'");
        expect(@"escape and bidi override are spelled out",
            PROMPT("sudo", "rm", "\x1b[2K", "safe‮gnp.sh"),
            @"sudo rm '\\u{1B}[2K' 'safe\\u{202E}gnp.sh'");
        expect(@"ordinary unicode is left alone", PROMPT("sudo", "cat", "/tmp/Übersicht/日本.txt"),
            @"sudo cat '/tmp/Übersicht/日本.txt'");
        expect(@"invalid UTF-8", PROMPT("sudo", "cat", "bad\xff\xfename"),
            @"sudo cat 'bad\\xFF\\xFEname'");
        expect(@"invisible letters, marks and symbols are spelled out",
            PROMPT("sudo", "cat", "/etc/hosts\xEF\xB8\x8F", "\xE3\x85\xA4", "a\xCD\x8F" "b", "\xE2\xA0\x80"),
            @"sudo cat '/etc/hosts\\u{FE0F}' '\\u{3164}' 'a\\u{34F}b' '\\u{2800}'");
        expect(@"argv[0] chosen by the caller is not shown", PROMPT("echo", "rm", "-rf", "/"),
            @"sudo rm -rf /");
        expect(@"no arguments at all", tid_look_build_prompt(0, (char *[]){NULL}, systemPath, home), @"sudo");

        /* Look-alike letters (see mark_lookalikes in pam_tid_look.m). */
        expect(@"a Cyrillic letter among Latin ones is spelled out", PROMPT("sudo", "/usr/bin/\xD1\x96" "d"),
            @"sudo '/usr/bin/\\u{456}d'");
        expect(@"so are Greek, Armenian and Cherokee ones",
            PROMPT("sudo", "/usr/bin/\xCE\xB9" "d", "f\xD6\x85" "o", "\xE1\x8E\xAA" "dmin"),
            @"sudo '/usr/bin/\\u{3B9}d' 'f\\u{585}o' '\\u{13AA}dmin'");
        expect(@"a combining mark does not split the run", PROMPT("sudo", "/usr/bin/\xD1\x96\xCC\x81" "d"),
            @"sudo '/usr/bin/\\u{456}\u0301d'");
        expect(@"letters and digits that NFKC changes are spelled out",
            PROMPT("sudo", "/usr/bin/\xEF\xBD\x89" "d", "\xF0\x9D\x90\xA2" "d", "\xE2\x84\xAA" "ill",
                "\xEF\xAC\x81" "le", "\xEF\xBC\x91"),
            @"sudo '/usr/bin/\\u{FF49}d' '\\u{1D422}d' '\\u{212A}ill' '\\u{FB01}le' '\\u{FF11}'");
        expect(@"words in one script other than Latin are left alone",
            PROMPT("sudo", "cat", "/tmp/\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82.txt", "\xCE\xB1\xCE\xB2\xCE\xB3", "\xD5\xA1\xD5\xA2"),
            @"sudo cat '/tmp/Привет.txt' 'αβγ' 'աբ'");
        expect(@"known limit: a run entirely in Cyrillic passes", PROMPT("sudo", "\xD1\x81\xD1\x81", "x.c"),
            @"sudo 'сс' x.c");

        NSArray<NSString *> *lines = [PROMPT("sudo", "true") componentsSeparatedByString:@"\n"];
        NSArray<NSString *> *labels = @[@"Command:", @"sudo true", @"", @"Found in PATH:", @"/usr/bin/true", @"",
            @"Directory:", @"*", @"", @"Requested by:", @"*", @"", @""]; /* "*": any text */
        BOOL laidOut = lines.count == labels.count;
        for (NSUInteger i = 0; laidOut && i < lines.count; i++) {
            NSString *line = [lines[i] stringByReplacingOccurrencesOfString:@"‎" withString:@""];
            laidOut = [labels[i] isEqualToString:@"*"] ? line.length > 0 : [line isEqualToString:labels[i]];
        }
        check(laidOut, @"each label on a line of its own, a blank line between sections",
            [lines componentsJoinedByString:@" | "]);
        NSString *rtl = command_of(PROMPT("sudo", "cp", "א", "ב"));
        check([rtl isEqualToString:@"sudo‎ cp‎ 'א'‎ 'ב'"],
            @"arguments are separated by left-to-right marks", rtl);

        /* sudo splits --preserve-env=A,B in place with strtok_r() before PAM runs. */
        char **cut = exec_layout(3, ARGV("sudo", "--preserve-env=TERM,,BASH_ENV", "bash"));
        char *last = NULL;
        for (char *t = strtok_r(cut[1] + strlen("--preserve-env="), ",", &last); t; t = strtok_r(NULL, ",", &last)) {}
        expect(@"arguments cut in place by sudo are shown whole", tid_look_build_prompt(3, cut, systemPath, home),
            @"sudo --preserve-env=TERM,,BASH_ENV bash");

        char longArg[2001];
        memset(longArg, 'A', 2000);
        longArg[2000] = '\0';
        NSString *longPrompt = PROMPT("sudo", "sh", "-c", longArg, "tail-marker");
        NSString *longLine = command_of(longPrompt);
        BOOL truncated = [longLine containsString:@"CHARACTERS NOT SHOWN"] &&
            [longLine hasSuffix:@"tail-marker"] && longLine.length < 450;
        if (!truncated) failures++;
        printf("%s  long command is cut in the middle (%lu chars shown)\n",
            truncated ? "ok  " : "FAIL", (unsigned long)longLine.length);

        /* One composed character sequence longer than the limit, at the start and at the end. */
        NSMutableData *marks = [NSMutableData dataWithBytes:"a" length:1];
        for (int i = 0; i < 2000; i++) [marks appendBytes:"\xCC\x81" length:2];
        NSMutableData *marksLast = [NSMutableData dataWithBytes:"x" length:1];
        [marksLast appendData:marks];
        for (NSData *arg in @[marks, marksLast]) {
            NSString *line = line_with_arg(arg, home);
            NSScanner *scan = [NSScanner scannerWithString:line];
            long long omitted = -1;
            [scan scanUpToString:@"…[" intoString:NULL];
            BOOL counted = [scan scanString:@"…[" intoString:NULL] && [scan scanLongLong:&omitted];
            check(line.length < 450 && counted && omitted > 0 && omitted < 4100,
                @"a long combining sequence is cut like any other text",
                [NSString stringWithFormat:@"%lu chars, %lld not shown", (unsigned long)line.length, omitted]);
        }

        /* Cuts never split a surrogate pair, whatever text comes before it. */
        BOOL whole = YES;
        for (int pad = 260; pad < 300; pad++) {
            NSMutableData *arg = [NSMutableData data];
            for (int i = 0; i < pad; i++) [arg appendBytes:"A" length:1];
            for (int i = 0; i < 200; i++) [arg appendBytes:"\xF0\x9F\x98\x80" length:4];
            NSString *line = line_with_arg(arg, home);
            if (!line.UTF8String || line.length > 410) whole = NO;
        }
        check(whole, @"cuts keep surrogate pairs whole", whole ? @"UTF-8 conversion works for every cut" : @"a cut split a pair");

        /* A deep working directory whose names are all escapes (U+200B) is cut too. */
        NSString *base = [NSTemporaryDirectory() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"tid_look_test.%d", getpid()]];
        NSString *deep = base;
        for (int level = 0; level < 4; level++) {
            deep = [deep stringByAppendingPathComponent:[@"" stringByPaddingToLength:60 withString:@"​" startingAtIndex:0]];
        }
        char saved[PATH_MAX];
        BOOL entered = getcwd(saved, sizeof saved) &&
            [NSFileManager.defaultManager createDirectoryAtPath:deep withIntermediateDirectories:YES attributes:nil error:NULL] &&
            chdir(deep.fileSystemRepresentation) == 0;
        NSString *dirLine = entered ? section(PROMPT("sudo", "true"), @"Directory:") : @"(could not enter the directory)";
        if (entered && chdir(saved) != 0) entered = NO;
        [NSFileManager.defaultManager removeItemAtPath:base error:NULL];
        check(entered && [dirLine containsString:@"CHARACTERS NOT SHOWN"] && dirLine.length < 260,
            @"a long working directory is cut in the middle",
            [NSString stringWithFormat:@"%lu chars: %@…", (unsigned long)dirLine.length, [dirLine substringToIndex:MIN(dirLine.length, 60)]]);

        /*
         * The PATH hint. Every PATH is given here, so the tests do not depend
         * on the caller's. The scratch directories belong to the user running
         * the tests, so a match in them can be changed without root; one in
         * /usr/bin or /bin cannot.
         */
        NSString *scratch = [NSTemporaryDirectory() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"tid_look_test.%d.path", getpid()]];
        NSString *evil = [scratch stringByAppendingPathComponent:@"evil"];
        NSString *lookalikeDir = [scratch stringByAppendingPathComponent:@"b\u0456n"];
        NSString *longDir = [scratch stringByAppendingPathComponent:[@"" stringByPaddingToLength:200 withString:@"d" startingAtIndex:0]];
        NSFileManager *fm = NSFileManager.defaultManager;
        BOOL made = YES;
        for (NSString *dir in @[evil, lookalikeDir, longDir, [evil stringByAppendingPathComponent:@"ls"]]) {
            made = made && [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
        }
        made = made && make_command([evil stringByAppendingPathComponent:@"id"], 0755) &&
            make_command([evil stringByAppendingPathComponent:@"FOO=1"], 0755) &&
            make_command([evil stringByAppendingPathComponent:@"whoami"], 0644) &&
            make_command([lookalikeDir stringByAppendingPathComponent:@"id"], 0755) &&
            make_command([longDir stringByAppendingPathComponent:@"id"], 0755) &&
            [fm createSymbolicLinkAtPath:[evil stringByAppendingPathComponent:@"idlink"] withDestinationPath:@"/usr/bin/id" error:NULL] &&
            [fm createSymbolicLinkAtPath:[scratch stringByAppendingPathComponent:@"loop"] withDestinationPath:@"loop" error:NULL];
        check(made, @"scratch commands for the PATH tests", scratch);

        NSString *changeable = @"Can be changed without root.";
        NSString *evilId = [NSString stringWithFormat:@"%@/id | %@", evil, changeable];
        char **evilFirst = ARGV(keep([NSString stringWithFormat:@"PATH=%@:/usr/bin:/bin", evil]));
        char **evilOnly = ARGV(keep([@"PATH=" stringByAppendingString:evil]));

        expect_hint(@"PATH lookup", PROMPT("sudo", "id", "-un"), @"/usr/bin/id");
        expect_hint(@"PATH lookup names the caller's copy", PROMPT_ENV(evilFirst, "sudo", "id", "-un"), evilId);
        expect(@"the command line stays as it was", PROMPT_ENV(evilFirst, "sudo", "id", "-un"), @"sudo id -un");
        expect_hint(@"a path with a / is not looked up", PROMPT_ENV(evilFirst, "sudo", "/usr/bin/id"), @"(none)");
        expect_hint(@"a relative path is not looked up either", PROMPT_ENV(evilFirst, "sudo", "./id"), @"(none)");
        expect_hint(@"a symbolic link only root can change", PROMPT_ENV(ARGV("PATH=/usr/bin"), "sudo", "vi"), @"/usr/bin/vi");
        expect_hint(@"a symbolic link in a folder the caller can change", PROMPT_ENV(evilOnly, "sudo", "idlink"),
            [NSString stringWithFormat:@"%@/idlink | %@", evil, changeable]);
        expect_hint(@"an earlier folder the caller can change is not flagged", PROMPT_ENV(evilFirst, "sudo", "true"),
            @"/usr/bin/true");
        expect_hint(@"a missing folder before the match",
            PROMPT_ENV(ARGV(keep([NSString stringWithFormat:@"PATH=%@/missing:/usr/bin", scratch])), "sudo", "id"), @"/usr/bin/id");
        expect_hint(@"a folder after the match is not used",
            PROMPT_ENV(ARGV(keep([NSString stringWithFormat:@"PATH=/usr/bin:%@", evil])), "sudo", "id"), @"/usr/bin/id");
        expect_hint(@"with -E", PROMPT_ENV(evilFirst, "sudo", "-E", "true"), @"/usr/bin/true");
        expect_hint(@"a file without an execute bit is skipped", PROMPT_ENV(evilFirst, "sudo", "whoami"), @"/usr/bin/whoami");
        expect_hint(@"a directory is skipped", PROMPT_ENV(evilFirst, "sudo", "ls"), @"/bin/ls");
        expect_hint(@"not found: no hint", PROMPT("sudo", "tid_look-no-such-command"), @"(none)");
        expect_hint(@"an error other than \"no such file\": no hint",
            PROMPT_ENV(ARGV(keep([NSString stringWithFormat:@"PATH=%@/loop:/usr/bin", scratch])), "sudo", "id"), @"(none)");
        expect_hint(@"a relative PATH entry: no hint", PROMPT_ENV(ARGV("PATH=bin:/usr/bin"), "sudo", "id"), @"(none)");
        expect_hint(@"a match only through \".\": no hint", PROMPT_ENV(ARGV("PATH=.:/tid_look-nonexistent"), "sudo", "id"), @"(none)");
        expect_hint(@"\".\" and empty entries are tried last", PROMPT_ENV(ARGV("PATH=.::/usr/bin"), "sudo", "id"), @"/usr/bin/id");
        expect_hint(@"no PATH: no hint", PROMPT_ENV(ARGV("HOME=/var/empty"), "sudo", "id"), @"(none)");
        expect_hint(@"no environment: no hint", PROMPT_ENV(NULL, "sudo", "id"), @"(none)");

        /* Two PATHs: sudoers searches the last non-empty PATH=. */
        expect_hint(@"two PATHs: the last one is searched",
            PROMPT_ENV(ARGV("PATH=/usr/bin", evilOnly[0]), "sudo", "id"), evilId);
        expect_hint(@"an empty last PATH is skipped", PROMPT_ENV(ARGV(evilOnly[0], "PATH="), "sudo", "id"), evilId);
        expect_hint(@"only empty PATHs: no hint", PROMPT_ENV(ARGV("PATH="), "sudo", "id"), @"(none)");
        expect_hint(@"a last PATH that is not UTF-8 is searched as it is",
            PROMPT_ENV(ARGV(evilOnly[0], "PATH=/tmp/\xff:/usr/bin"), "sudo", "id"), @"/usr/bin/id");
        expect_hint(@"another name starting with PATH does not count",
            PROMPT_ENV(ARGV("PATH=/usr/bin", keep([@"PATHX=" stringByAppendingString:evil])), "sudo", "id"), @"/usr/bin/id");

        /* Finding the command word in sudo's arguments. */
        expect_hint(@"options and -u root are skipped", PROMPT_ENV(evilFirst, "sudo", "-u", "root", "-H", "id", "-un"), evilId);
        expect_hint(@"grouped flags with a value", PROMPT_ENV(evilFirst, "sudo", "-Eu", "root", "id"), evilId);
        expect_hint(@"a value attached to its flag", PROMPT_ENV(evilFirst, "sudo", "-uroot", "-p", "x y", "id"), evilId);
        expect_hint(@"-u with root's uid", PROMPT_ENV(evilFirst, "sudo", "-u", "#00", "id"), evilId);
        expect_hint(@"VAR=value words are skipped", PROMPT_ENV(evilFirst, "sudo", "FOO=1", "-n", "BAR=x=y", "id"), evilId);
        expect_hint(@"a word after -- is the command", PROMPT_ENV(evilFirst, "sudo", "-n", "--", "FOO=1", "id"),
            [NSString stringWithFormat:@"%@/FOO=1 | %@", evil, changeable]);
        expect_hint(@"-- as an option's value counts too", PROMPT_ENV(evilFirst, "sudo", "-p", "--", "FOO=1", "id"),
            [NSString stringWithFormat:@"%@/FOO=1 | %@", evil, changeable]);
        expect_hint(@"argv[0] is not the word before", PROMPT_ENV(evilFirst, "--", "FOO=1", "id"), evilId);
        expect_hint(@"-k with a command", PROMPT_ENV(evilFirst, "sudo", "-k", "id"), evilId);
        const char *noHint[][5] = {
            {"-u", "nobody", "id"}, {"-u", "#1", "id"}, {"-u", "root", "-u", "root", "id"}, {"-g", "staff", "id"},
            {"-s", "id"}, {"-i", "id"}, {"-e", "id"}, {"-l", "id"}, {"-v"}, {"-K"}, {"-V"}, {"-h"},
            {"-D", "/tmp", "id"}, {"-R", "/tmp", "id"}, {"-U", "nobody", "-l", "id"}, {"-a", "x", "id"},
            {"-c", "x", "id"}, {"-r", "x", "id"}, {"-t", "x", "id"}, {"-X", "id"}, {"-k"}, {"-p"},
            {"--user=root", "id"}, {"--preserve-env", "id"}, {"--non-interactive", "id"},
            {"PATH=/usr/bin", "id"}, {"=x", "id"},
        };
        for (size_t t = 0; t < sizeof noHint / sizeof *noHint; t++) {
            char *args[7] = {"sudo"};
            NSMutableArray<NSString *> *words = [NSMutableArray arrayWithObject:@"sudo"];
            int n = 1;
            for (int k = 0; k < 5 && noHint[t][k]; k++) {
                args[n++] = (char *)noHint[t][k];
                [words addObject:@(noHint[t][k])];
            }
            expect_hint([@"no hint for " stringByAppendingString:[words componentsJoinedByString:@" "]],
                tid_look_build_prompt(n, exec_layout(n, args), evilFirst, home), @"(none)");
        }
        const char *program = getprogname();
        setprogname("sudoedit");
        expect_hint(@"no hint for sudoedit", PROMPT_ENV(evilFirst, "sudoedit", "id"), @"(none)");
        setprogname(program);

        /* How the file is shown. */
        expect_hint(@"look-alike letters in the file are spelled out",
            PROMPT_ENV(ARGV(keep([@"PATH=" stringByAppendingString:lookalikeDir])), "sudo", "id"),
            [NSString stringWithFormat:@"%@/b\\u{456}n/id | %@", scratch, changeable]);
        expect_hint(@"the user's home is written as ~",
            tid_look_build_prompt(2, exec_layout(2, ARGV("sudo", "id")), evilOnly, scratch.fileSystemRepresentation),
            [NSString stringWithFormat:@"~/evil/id | %@", changeable]);
        NSString *longHint = hint_of(PROMPT_ENV(ARGV(keep([@"PATH=" stringByAppendingString:longDir])), "sudo", "id"));
        check([longHint containsString:@"CHARACTERS NOT SHOWN"] && [longHint containsString:@"ddd/id | "] && longHint.length < 260,
            @"a long file name is cut in the middle", longHint);
        NSArray<NSString *> *warned = [PROMPT_ENV(evilOnly, "sudo", "id") componentsSeparatedByString:@"\n"];
        check(warned.count > 7 && [warned[3] isEqualToString:@"Found in PATH:"] && [warned[5] isEqualToString:changeable] &&
            [warned[6] isEqualToString:@""] && [warned[7] isEqualToString:@"Directory:"],
            @"the warning has a line of its own, before the blank line", [warned componentsJoinedByString:@" | "]);
        [fm removeItemAtPath:scratch error:NULL];

        /* The environment as exec passed it, read back by the module. */
        char **twoPaths = ARGV("PATH=/usr/bin", "A=1", "PATH=", "PATH=/tmp/x");
        NSString *asPassed = printed(run_self(ARGV("tid_look_test", "--print-environment", "plain"), twoPaths), @[@"PATH", @"A"]);
        check([asPassed isEqualToString:@"PATH=/usr/bin A=1 PATH= PATH=/tmp/x"],
            @"the environment is read as exec passed it, duplicates kept", asPassed);
        NSString *emptyName = run_self(ARGV("", "--print-environment", "plain"), twoPaths);
        check([emptyName isEqualToString:@"(none)\n"], @"no environment with an empty argv[0]", printed(emptyName, @[@"PATH", @"A"]));
        NSString *cutArg = run_self(ARGV("tid_look_test", "--print-environment", "TERM,PATH", "last"), twoPaths);
        check([cutArg isEqualToString:@"(none)\n"], @"no environment when an argument was cut in place", printed(cutArg, @[@"PATH", @"A"]));
        /* Each piece matches an argument here; only where the arguments start tells the cut. */
        NSString *cutPath = run_self(ARGV("tid_look_test", "--print-environment", "X,PATH=/tmp/evil", "PATH=/tmp/evil"), ARGV("A=1"));
        check([cutPath isEqualToString:@"(none)\n"], @"an argument cut in place is not read as the environment",
            printed(cutPath, @[@"PATH", @"A"]));

        /* What sudo's policy may change about the search. */
        NSString *policy = [NSTemporaryDirectory() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"tid_look_test.%d.policy", getpid()]];
        NSString *included = [policy stringByAppendingPathComponent:@"sudoers.d"];
        [fm createDirectoryAtPath:included withIntermediateDirectories:YES attributes:nil error:NULL];
        char *noConf = keep([policy stringByAppendingPathComponent:@"missing.conf"]);
        char *stock = write_file(policy, @"stock", [NSString stringWithFormat:
            @"Defaults env_reset\n# Defaults secure_path=\"/usr/bin\"\n%%admin ALL = (ALL) ALL\n#includedir %@\n", included]);
        write_file(included, @"local", @"Defaults timestamp_timeout=0\n");
        check(tid_look_policy_uses_path(noConf, stock), @"a policy like macOS's searches PATH", @(stock));
        char *secure = write_file(policy, @"secure", @"Defaults\tsecure_path=\"/usr/bin:/bin\"\n");
        check(!tid_look_policy_uses_path(noConf, secure), @"secure_path: no hint", @(secure));
        char *runas = write_file(policy, @"runas", @"Defaults RUNAS_DEFAULT=nobody\n");
        check(!tid_look_policy_uses_path(noConf, runas), @"runas_default, in any case: no hint", @(runas));
        write_file(included, @"secure", @"Defaults secure_path=/usr/bin\n");
        check(!tid_look_policy_uses_path(noConf, stock), @"secure_path in an included directory: no hint", @(stock));
        char *missing = write_file(policy, @"missing", @"@include tid_look-missing\n");
        check(!tid_look_policy_uses_path(noConf, missing), @"an include that cannot be read: no hint", @(missing));
        char *quoted = write_file(policy, @"quoted", @"@include \"local\"\n");
        check(!tid_look_policy_uses_path(noConf, quoted), @"an include it does not follow: no hint", @(quoted));
        char *plain = write_file(policy, @"plain", @"Defaults env_reset\n");
        char *plugin = write_file(policy, @"sudo.conf", @"Plugin sudoers_policy sudoers.so\n");
        check(!tid_look_policy_uses_path(plugin, plain), @"a plugin in sudo.conf: no hint", @(plugin));
        char *noPlugin = write_file(policy, @"sudo2.conf", @"Set disable_coredump false\n");
        check(tid_look_policy_uses_path(noPlugin, plain), @"sudo.conf without a plugin", @(noPlugin));
        check(!tid_look_policy_uses_path(noConf, noConf), @"no sudoers: no hint", @(noConf));
        [fm removeItemAtPath:policy error:NULL];

        expect_timeout(@"no options: default timeout", 30, 0, (const char *[]){NULL});
        expect_timeout(@"timeout=5", 5, 1, (const char *[]){"timeout=5"});
        expect_timeout(@"timeout=0 turns it off", 0, 1, (const char *[]){"timeout=0"});
        expect_timeout(@"timeout=3600 is the maximum", 3600, 1, (const char *[]){"timeout=3600"});
        expect_timeout(@"the last valid value wins", 7, 3, (const char *[]){"timeout=5", "timeout=7", "timeout=x"});
        expect_timeout(@"unknown options are ignored", 9, 2, (const char *[]){"debug", "timeout=9"});
        const char *invalid[] = {"timeout=3601", "timeout=", "timeout=-1", "timeout=+5", "timeout=5s",
            "timeout=1.5", "timeout=00005", "timeout=99999999999999999999", "Timeout=5", "timeout"};
        for (size_t i = 0; i < sizeof invalid / sizeof *invalid; i++) {
            expect_timeout([NSString stringWithFormat:@"%s keeps the default", invalid[i]], 30, 1, &invalid[i]);
        }

        printf("\nFull prompt for a plain command:\n---\n%s---\n",
            PROMPT("sudo", "brew", "services", "restart", "nginx").UTF8String);

        /*
         * An exception in the module must not end sudo. The private Touch ID
         * check is made to throw; the module must give up so that sudo asks
         * for the password. It shows no dialog: should the check not throw
         * after all, authd refuses sudo's right at once outside sudo.
         */
        Method evaluate = class_getInstanceMethod(NSClassFromString(@"LAContext"),
            NSSelectorFromString(@"evaluatePolicy:options:error:"));
        auditinfo_addr_t session = {0};
        BOOL owner = getaudit_addr(&session, sizeof session) == 0 && (session.ai_flags & 0x0010) &&
            session.ai_auid == getuid();
        struct pam_conv conv = {no_conversation, NULL};
        pam_handle_t *pamh = NULL;
        if (evaluate && owner &&
            pam_start("tid_look_test", getpwuid(getuid())->pw_name, &conv, &pamh) == PAM_SUCCESS) {
            __block BOOL thrown = NO;
            IMP original = method_setImplementation(evaluate,
                imp_implementationWithBlock(^id(id context, NSInteger policy, NSDictionary *options, NSError **error) {
                    thrown = YES;
                    @throw [NSException exceptionWithName:@"TestException" reason:@"thrown by the test" userInfo:nil];
                }));
            int result = pam_sm_authenticate(pamh, 0, 0, NULL);
            method_setImplementation(evaluate, original);
            pam_end(pamh, PAM_SUCCESS);
            check(thrown && result == PAM_AUTHINFO_UNAVAIL, @"an exception in the module makes sudo ask for the password",
                [NSString stringWithFormat:@"%s, PAM result %d (wanted %d)", thrown ? "thrown" : "not thrown",
                    result, PAM_AUTHINFO_UNAVAIL]);
        } else {
            printf("skip  an exception in the module makes sudo ask for the password\n"
                   "      (needs a GUI session owned by this user)\n");
        }

        BOOL usable = tid_look_touchid_usable(getuid());
        printf("\nTouch ID usable for uid %d (non-interactive check): %s\n", getuid(), usable ? "yes" : "no");

        printf("\n%s\n", failures ? "FAILED" : "all checks passed");
        return failures ? 1 : 0;
    }
}
