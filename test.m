/* Checks the parts of pam_tidcmd that can run outside sudo. Shows no dialog. */

#import <Foundation/Foundation.h>
#import <pwd.h>

NSString *tidcmd_build_prompt(int argc, char **argv, const char *home);
BOOL tidcmd_touchid_usable(uid_t uid);

static int failures;

static void expect(NSString *label, NSString *prompt, NSString *wanted) {
    NSString *firstLine = [prompt componentsSeparatedByString:@"\n"].firstObject;
    BOOL ok = [firstLine isEqualToString:wanted];
    if (!ok) failures++;
    printf("%s  %s\n      got:    %s\n", ok ? "ok  " : "FAIL", label.UTF8String, firstLine.UTF8String);
    if (!ok) printf("      wanted: %s\n", wanted.UTF8String);
}

#define ARGV(...) ((char *[]){__VA_ARGS__, NULL})
#define COUNT(...) ((int)(sizeof((char *[]){__VA_ARGS__}) / sizeof(char *)))
#define PROMPT(...) tidcmd_build_prompt(COUNT(__VA_ARGS__), ARGV(__VA_ARGS__), home)

int main(void) {
    @autoreleasepool {
        const char *home = getpwuid(getuid())->pw_dir;

        expect(@"plain command", PROMPT("sudo", "brew", "services", "restart", "nginx"),
            @"Command: sudo brew services restart nginx");
        expect(@"sudo flags are kept", PROMPT("sudo", "-u", "postgres", "-E", "psql"),
            @"Command: sudo -u postgres -E psql");
        expect(@"spaces and quotes", PROMPT("sudo", "sh", "-c", "echo 'hi there' > /etc/x"),
            @"Command: sudo sh -c 'echo '\\''hi there'\\'' > /etc/x'");
        expect(@"empty argument", PROMPT("sudo", "touch", ""), @"Command: sudo touch ''");
        expect(@"newline cannot start a fake line", PROMPT("sudo", "true", "a\nCommand: ls"),
            @"Command: sudo true 'a\\u{A}Command: ls'");
        expect(@"escape and bidi override are spelled out",
            PROMPT("sudo", "rm", "\x1b[2K", "safe‮gnp.sh"),
            @"Command: sudo rm '\\u{1B}[2K' 'safe\\u{202E}gnp.sh'");
        expect(@"ordinary unicode is left alone", PROMPT("sudo", "cat", "/tmp/Übersicht/日本.txt"),
            @"Command: sudo cat '/tmp/Übersicht/日本.txt'");
        expect(@"invalid UTF-8", PROMPT("sudo", "cat", "bad\xff\xfename"),
            @"Command: sudo cat 'bad\\xFF\\xFEname'");

        char longArg[2001];
        memset(longArg, 'A', 2000);
        longArg[2000] = '\0';
        NSString *longPrompt = PROMPT("sudo", "sh", "-c", longArg, "tail-marker");
        NSString *longLine = [longPrompt componentsSeparatedByString:@"\n"].firstObject;
        BOOL truncated = [longLine containsString:@"CHARACTERS NOT SHOWN"] &&
            [longLine hasSuffix:@"tail-marker"] && longLine.length < 450;
        if (!truncated) failures++;
        printf("%s  long command is cut in the middle (%lu chars shown)\n",
            truncated ? "ok  " : "FAIL", (unsigned long)longLine.length);

        printf("\nFull prompt for a plain command:\n---\n%s---\n",
            PROMPT("sudo", "brew", "services", "restart", "nginx").UTF8String);

        BOOL usable = tidcmd_touchid_usable(getuid());
        printf("\nTouch ID usable for uid %d (non-interactive check): %s\n", getuid(), usable ? "yes" : "no");

        printf("\n%s\n", failures ? "FAILED" : "all checks passed");
        return failures ? 1 : 0;
    }
}
