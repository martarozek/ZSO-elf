CC = gcc
CFLAGS = -fPIC -g -Wl,-soname=$(TARGET_LIB) -std=c99
LDFLAGS = -shared
RM = rm -f
TARGET_LIB = libinterceptor.so

SRCS = interceptor.c

all: ${TARGET_LIB}

$(TARGET_LIB): $(SRCS)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	-$(RM) $(TARGET_LIB)
