# Makefile for Composite Provider
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -fPIC -std=c99 -O2
LDFLAGS = -shared
INCLUDES = $(EXTRA_INCLUDE) -I./include -I/usr/include/openssl
PREFIX = /opt/crypto
LIBS = -lcrypto

# Source files
SOURCES = src/provider.c \
		  src/provider_ctx.c \
          src/composite_sig.c \
		  src/composite_sig_key.c \
		  src/composite_sig_encoding.c \
          src/composite_kem.c \
		  src/composite_kem_key.c \
		  src/composite_kem_encoding.c \
          src/mldsa_composite.c \
          src/mlkem_composite.c

# Object files
OBJECTS = $(SOURCES:.c=.o)

# Output
TARGET = composite.so

.PHONY: all clean test install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f tests/test_provider

test: $(TARGET)
	$(MAKE) -C tests

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/lib/ossl-modules
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/lib/ossl-modules/

.PHONY: help
help:
	@echo "Composite Provider Build System"
	@echo "Available targets:"
	@echo "  all      - Build the provider library (default)"
	@echo "  clean    - Remove built files"
	@echo "  test     - Build and run tests"
	@echo "  install  - Install the provider"
	@echo "  help     - Show this help message"
