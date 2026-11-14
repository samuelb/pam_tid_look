/* Checks the parts of pam_tidcmd that can run outside sudo. Shows no dialog. */

#import <Foundation/Foundation.h>
#import <pwd.h>

NSString *tidcmd_build_prompt(int argc, char **argv, const char *home);
BOOL tidcmd_touchid_usable(uid_t uid);
unsigned tidcmd_timeout(int argc, const char **argv);

static int failures;

/* The line after a label line, such as the command line after "Command:". */
static NSString *section(NSString *prompt, NSString *label) {
    NSArray<NSString *> *lines = [prompt componentsSeparatedByString:@"\n"];
    NSUInteger i = [lines indexOfObject:label];
    return i != NSNotFound && i + 1 < lines.count ? lines[i + 1] : @"(no such section)";
}

static NSString *command_of(NSString *prompt) {
    return section(prompt, @"Command:");
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
    return command_of(tidcmd_build_prompt(3, exec_layout(3, (char *[]){"sudo", "echo", bytes.mutableBytes}), home));
}

/* The timeout read from the given module options. */
static void expect_timeout(NSString *label, unsigned wanted, int argc, const char **argv) {
    unsigned got = tidcmd_timeout(argc, argv);
    check(got == wanted, label, [NSString stringWithFormat:@"%u seconds (wanted %u)", got, wanted]);
}

#define ARGV(...) ((char *[]){__VA_ARGS__, NULL})
#define COUNT(...) ((int)(sizeof((char *[]){__VA_ARGS__}) / sizeof(char *)))
#define PROMPT(...) tidcmd_build_prompt(COUNT(__VA_ARGS__), exec_layout(COUNT(__VA_ARGS__), ARGV(__VA_ARGS__)), home)

int main(void) {
    @autoreleasepool {
        const char *home = getpwuid(getuid())->pw_dir;

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
        expect(@"no arguments at all", tidcmd_build_prompt(0, (char *[]){NULL}, home), @"sudo");

        NSArray<NSString *> *lines = [PROMPT("sudo", "true") componentsSeparatedByString:@"\n"];
        NSArray<NSString *> *labels = @[@"Command:", @"sudo true", @"", @"Directory:", @"*", @"",
            @"Requested by:", @"*", @"", @""]; /* "*": any text */
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
        expect(@"arguments cut in place by sudo are shown whole", tidcmd_build_prompt(3, cut, home),
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
            [NSString stringWithFormat:@"tidcmd_test.%d", getpid()]];
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

        BOOL usable = tidcmd_touchid_usable(getuid());
        printf("\nTouch ID usable for uid %d (non-interactive check): %s\n", getuid(), usable ? "yes" : "no");

        printf("\n%s\n", failures ? "FAILED" : "all checks passed");
        return failures ? 1 : 0;
    }
}
