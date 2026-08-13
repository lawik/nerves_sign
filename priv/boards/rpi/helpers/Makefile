# Build the key helper(s). nerves_sign drives this with the musl Nerves
# toolchain (CC) and static linking; see NervesSign.Initramfs / Toolchain.
#
#   make CC=aarch64-nerves-linux-musl-gcc
#
# Static by default so no libc ships in the CPIO.

CFLAGS ?= -Wall -Wextra -Os
LDFLAGS ?= -static
TARGET = unlock
OBJS = unlock.o otp.o mailbox.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Host tests for the logic above the mailbox, built with the host compiler and
# an in-memory fake. Not cross-compiled and not shipped.
HOST_CC ?= cc
TEST_BIN = tests/otp_test

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): tests/otp_test.c tests/fake_mailbox.c otp.c
	$(HOST_CC) -Wall -Wextra -O1 -g -o $@ $^

clean:
	$(RM) $(TARGET) $(OBJS) $(TEST_BIN)

.PHONY: all clean test
