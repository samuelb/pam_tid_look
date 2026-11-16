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
SANITIZE = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
SANITIZE_ENV = ASAN_OPTIONS=external_symbolizer_path=/usr/bin/atos UBSAN_OPTIONS=print_stacktrace=1

# Everything is built in build/. The installer, the module and the probe end
# up side by side there, as in Homebrew's libexec and in
# /Library/Security/pam_tid_look, so `sudo build/pam_tid_look install` runs
# the installer the way users run it.
B = build

all: $(B)/pam_tid_look.so $(B)/pam_tid_look_probe $(B)/pam_tid_look

$(B)/pam_tid_look.so: src/pam_tid_look.m
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(ARCHS) -bundle -o $@ $< $(LIBS)
	codesign --force --sign - $@

# The installer's load check. Built for the module's architectures, so that on
# Apple silicon it runs as arm64e and loads the slice sudo loads.
$(B)/pam_tid_look_probe: src/pam_tid_look_probe.c
	@mkdir -p $(B)
	$(CC) $(PROBE_CFLAGS) $(ARCHS) -o $@ $< -lpam
	codesign --force --sign - $@

$(B)/pam_tid_look: src/pam_tid_look.sh
	@mkdir -p $(B)
	install -m 755 $< $@

$(B)/prompt_test: src/pam_tid_look.m test/prompt_test.m
	@mkdir -p $(B)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(B)/prompt_test_sanitized: src/pam_tid_look.m test/prompt_test.m
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(SANITIZE) -o $@ $^ $(LIBS)

# Shows no dialog and needs no root.
test: analyze sanitize $(B)/prompt_test $(B)/pam_tid_look.so $(B)/pam_tid_look_probe
	./$(B)/prompt_test
	./$(B)/pam_tid_look_probe module ./$(B)/pam_tid_look.so
	/bin/bash ./test/install_test.sh
	/bin/bash ./test/render_formula_test.sh

# Clang's static analyzer on every source file. Any finding fails.
analyze:
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null src/pam_tid_look.m
	$(CC) $(PROBE_CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null src/pam_tid_look_probe.c
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null test/prompt_test.m
	$(CC) $(CFLAGS) --analyze -Xclang -analyzer-werror -o /dev/null test/dialog_check.m

# The prompt tests again, built with AddressSanitizer and
# UndefinedBehaviorSanitizer. Any finding ends the run and fails.
sanitize: $(B)/prompt_test_sanitized
	$(SANITIZE_ENV) ./$(B)/prompt_test_sanitized

lint:
	shellcheck -s bash src/pam_tid_look.sh test/install_test.sh scripts/render_formula.sh scripts/screenshot.sh test/render_formula_test.sh

# Raises real authorization dialogs for a moment. See test/dialog_check.m.
$(B)/dialog_check: test/dialog_check.m src/pam_tid_look.m
	@mkdir -p $(B)
	$(CC) $(CFLAGS) -o $@ $^ -framework CoreGraphics $(LIBS)

dialog-check: $(B)/dialog_check
	./$(B)/dialog_check

clean:
	rm -rf $(B)

.PHONY: all test analyze sanitize lint dialog-check clean
