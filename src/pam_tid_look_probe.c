/*
 * pam_tid_look_probe: checks that PAM can load a module or a policy, without
 * authenticating, showing anything or asking for anything.
 *
 *   pam_tid_look_probe module PATH
 *       Loads PATH the way OpenPAM does (dlopen with RTLD_NOW) and looks up
 *       pam_sm_authenticate.
 *
 *   pam_tid_look_probe policy /etc/pam.d/NAME
 *       Calls pam_start() for the service NAME. OpenPAM reads the policy and
 *       loads every module it names, following includes, in pam_start(). If
 *       one of them cannot be loaded, pam_start() fails, and so would sudo,
 *       with "unable to initialize PAM".
 *
 * Exits 0 if it loads, 1 if not, 2 on a usage error.
 *
 * OpenPAM on macOS only takes service names, not paths, so a policy to check
 * has to be in /etc/pam.d. A service without a policy file falls back to
 * "other" and loads fine, so the file is required to exist.
 *
 * Built for the same architectures as the module. On Apple silicon it then
 * runs as arm64e and loads the module's arm64e slice, as sudo does.
 */

#include <dlfcn.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char kPolicyDir[] = "/etc/pam.d/";

static int no_conversation(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    return PAM_CONV_ERR;
}

static int check_module(const char *path) {
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }
    int ok = dlsym(handle, "pam_sm_authenticate") != NULL;
    if (!ok) fprintf(stderr, "%s: no pam_sm_authenticate\n", path);
    dlclose(handle);
    return ok ? 0 : 1;
}

static int check_policy(const char *path) {
    const char *service = path + strlen(kPolicyDir);
    if (strncmp(path, kPolicyDir, strlen(kPolicyDir)) != 0 || *service == '\0' || strchr(service, '/')) {
        fprintf(stderr, "%s: the policy must be a file in %s\n", path, kPolicyDir);
        return 2;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "%s: no such policy file\n", path);
        return 1;
    }
    struct pam_conv conv = {no_conversation, NULL};
    pam_handle_t *pamh = NULL;
    int status = pam_start(service, NULL, &conv, &pamh);
    if (status != PAM_SUCCESS) {
        fprintf(stderr, "%s: %s\n", path, pam_strerror(pamh, status));
    }
    if (pamh) pam_end(pamh, status);
    return status == PAM_SUCCESS ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "module") == 0) return check_module(argv[2]);
    if (argc == 3 && strcmp(argv[1], "policy") == 0) return check_policy(argv[2]);
    fprintf(stderr, "usage: %s module PATH | policy /etc/pam.d/NAME\n", argv[0]);
    return 2;
}
