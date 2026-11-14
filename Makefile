CC      = xcrun clang
WARN    = -Wall -Wextra -Wno-unused-parameter
CFLAGS  = -fobjc-arc -O2 $(WARN) -fvisibility=hidden -mmacosx-version-min=14.0
LIBS    = -framework Foundation -framework LocalAuthentication -framework Security -lpam -licucore
# /usr/bin/sudo is arm64e on Apple silicon and x86_64 on Intel.
ARCHS   = -arch arm64e -arch arm64 -arch x86_64

all: pam_tidcmd.so pam_tidcmd_probe

pam_tidcmd.so: pam_tidcmd.m
	$(CC) $(CFLAGS) $(ARCHS) -bundle -o $@ $< $(LIBS)
	codesign --force --sign - $@

# The installer's load check. Built for the module's architectures, so that on
# Apple silicon it runs as arm64e and loads the slice sudo loads.
pam_tidcmd_probe: pam_tidcmd_probe.c
	$(CC) -O2 $(WARN) -mmacosx-version-min=14.0 $(ARCHS) -o $@ $< -lpam
	codesign --force --sign - $@

tidcmd_test: pam_tidcmd.m test.m
	$(CC) $(CFLAGS) -o $@ pam_tidcmd.m test.m $(LIBS)

# Shows no dialog and needs no root.
test: tidcmd_test pam_tidcmd.so pam_tidcmd_probe
	./tidcmd_test
	./pam_tidcmd_probe module ./pam_tidcmd.so
	/bin/bash ./install_test.sh

lint:
	shellcheck -s bash pam_tidcmd.sh install_test.sh

# Raises real authorization dialogs for a moment. See dialog_check.m.
dialog_check: dialog_check.m pam_tidcmd.m
	$(CC) $(CFLAGS) -o $@ dialog_check.m pam_tidcmd.m -framework CoreGraphics $(LIBS)

dialog-check: dialog_check
	./dialog_check

clean:
	rm -f pam_tidcmd.so pam_tidcmd_probe tidcmd_test dialog_check

.PHONY: all test lint dialog-check clean
