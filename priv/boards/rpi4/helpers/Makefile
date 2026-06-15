# Build the key helper(s). nerves_sign drives this with the musl Nerves
# toolchain (CC) and static linking; see NervesSign.Initramfs / Toolchain.
#
#   make CC=aarch64-nerves-linux-musl-gcc
#
# Static by default so no libc ships in the CPIO.

CFLAGS ?= -Wall -Wextra -Os
LDFLAGS ?= -static
TARGET = unlock

all: $(TARGET)

$(TARGET): unlock.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) $(TARGET)

.PHONY: all clean
