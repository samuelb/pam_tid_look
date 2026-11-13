CC      = xcrun clang
CFLAGS  = -fobjc-arc -O2 -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -mmacosx-version-min=14.0
LIBS    = -framework Foundation -framework LocalAuthentication -framework Security -lpam
# /usr/bin/sudo is arm64e on Apple silicon and x86_64 on Intel.
ARCHS   = -arch arm64e -arch arm64 -arch x86_64

all: pam_tidcmd.so

pam_tidcmd.so: pam_tidcmd.m
	$(CC) $(CFLAGS) $(ARCHS) -bundle -o $@ $< $(LIBS)
	codesign --force --sign - $@

tidcmd_test: pam_tidcmd.m test.m
	$(CC) $(CFLAGS) -o $@ pam_tidcmd.m test.m $(LIBS)

test: tidcmd_test
	./tidcmd_test

clean:
	rm -f pam_tidcmd.so tidcmd_test

.PHONY: all test clean
