# Build the key helper(s). nerves_sign drives this with the musl Nerves
# toolchain (CC) and static linking; see NervesSign.Initramfs / Toolchain.
#
#   make CC=aarch64-nerves-linux-musl-gcc
#
# Static by default so no libc ships in the CPIO.

CFLAGS ?= -Wall -Wextra -Os
LDFLAGS ?= -static
# unlock: reads an existing key. bootstrap-or-derive: also provisions a blank
# device and converts a plaintext rootfs on first boot.
TARGETS = unlock bootstrap-or-derive

UNLOCK_OBJS = unlock.o otp.o mailbox.o
BOOTSTRAP_OBJS = bootstrap_main.o bootstrap.o blockdev.o crypt.o dmcrypt.o otp.o mailbox.o

all: $(TARGETS)

unlock: $(UNLOCK_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(UNLOCK_OBJS)

bootstrap-or-derive: $(BOOTSTRAP_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BOOTSTRAP_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Host tests for the logic above the mailbox, built with the host compiler and
# an in-memory fake. Not cross-compiled and not shipped.
HOST_CC ?= cc
HOST_CFLAGS ?= -Wall -Wextra -O1 -g
TEST_BINS = tests/otp_test tests/bootstrap_test

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do ./$$t || exit 1; done

tests/otp_test: tests/otp_test.c tests/fake_mailbox.c otp.c
	$(HOST_CC) $(HOST_CFLAGS) -o $@ $^

# The conversion logic against a reversible stand-in for dm-crypt. Regular
# files stand in for the partitions; everything above the crypt seam is
# ordinary file I/O, so it behaves the same either way.
tests/bootstrap_test: tests/bootstrap_test.c tests/fake_crypt.c bootstrap.c blockdev.c
	$(HOST_CC) $(HOST_CFLAGS) -o $@ $^

clean:
	$(RM) $(TARGETS) $(UNLOCK_OBJS) $(BOOTSTRAP_OBJS) $(TEST_BINS)

.PHONY: all clean test
