CC      = xcrun clang
WARN    = -Wall -Wextra -Wno-unused-parameter
CFLAGS  = -fobjc-arc -O2 $(WARN) -fvisibility=hidden -mmacosx-version-min=14.0
PROBE_CFLAGS = -O2 $(WARN) -mmacosx-version-min=14.0
LIBS    = -framework Foundation -framework LocalAuthentication -framework Security -lpam -licucore
# /usr/bin/sudo is arm64e on Apple silicon and x86_64 on Intel.
ARCHS   = -arch arm64e -arch arm64 -arch x86_64
# The sanitized test build. -O1 and frame pointers, as ASan's docs advise, for
# readable traces; no -arch, so it is built for this Mac only. Traces go
# through the system's atos, whatever llvm-symbolizer PATH may hold.
# The analyze and sanitize recipes are modelled on those in the justfile of
# https://github.com/samuelb/macos-sudo-touchid-context, which is under the MIT
# License, Copyright (c) 2026 Lauri Gates.
SANITIZE = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
SANITIZE_ENV = ASAN_OPTIONS=external_symbolizer_path=/usr/bin/atos UBSAN_OPTIONS=print_stacktrace=1

all: pam_tid_look.so pam_tid_look_probe

pam_tid_look.so: pam_tid_look.m
	$(CC) $(CFLAGS) $(ARCHS) -bundle -o $@ $< $(LIBS)
	codesign --force --sign - $@

# The installer's load check. Built for the module's architectures, so that on
# Apple silicon it runs as arm64e and loads the slice sudo loads.
pam_tid_look_probe: pam_tid_look_probe.c
	$(CC) $(PROBE_CFLAGS) $(ARCHS) -o $@ $< -lpam
	codesign --force --sign - $@

tid_look_test: pam_tid_look.m test.m
	$(CC) $(CFLAGS) -o $@ pam_tid_look.m test.m $(LIBS)

tid_look_test_sanitized: pam_tid_look.m test.m
	$(CC) $(CFLAGS) $(SANITIZE) -o $@ pam_tid_look.m test.m $(LIBS)

# Shows no dialog and needs no root.
test: analyze sanitize tid_look_test pam_tid_look.so pam_tid_look_probe
	./tid_look_test
	./pam_tid_look_probe module ./pam_tid_look.so
	/bin/bash ./install_test.sh
	/bin/bash ./render_formula_test.sh

# Clang's static analyzer on every source file. Any finding fails.
analyze:
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null pam_tid_look.m
	$(CC) $(PROBE_CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null pam_tid_look_probe.c
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null test.m
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null dialog_check.m

# The prompt tests again, built with AddressSanitizer and
# UndefinedBehaviorSanitizer. Any finding ends the run and fails.
sanitize: tid_look_test_sanitized
	$(SANITIZE_ENV) ./tid_look_test_sanitized

lint:
	shellcheck -s bash pam_tid_look.sh install_test.sh render_formula.sh render_formula_test.sh

# Raises real authorization dialogs for a moment. See dialog_check.m.
dialog_check: dialog_check.m pam_tid_look.m
	$(CC) $(CFLAGS) -o $@ dialog_check.m pam_tid_look.m -framework CoreGraphics $(LIBS)

dialog-check: dialog_check
	./dialog_check

clean:
	rm -f pam_tid_look.so pam_tid_look_probe tid_look_test tid_look_test_sanitized dialog_check
	rm -rf tid_look_test_sanitized.dSYM

.PHONY: all test analyze sanitize lint dialog-check clean
