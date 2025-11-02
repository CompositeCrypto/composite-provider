# Makefile for Composite Provider
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -fPIC -std=c99 -O2
LDFLAGS = -shared
INCLUDES = -I./include -I/usr/include/openssl
LIBS = -lcrypto

# Source files
SOURCES = src/provider.c \
          src/composite_sig.c \
          src/composite_kem.c \
          src/mldsa_composite.c \
          src/mlkem_composite.c \
		  src/composite_keys.c

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
	install -d $(DESTDIR)/usr/lib/ossl-modules
	install -m 755 $(TARGET) $(DESTDIR)/usr/lib/ossl-modules/

.PHONY: help
help:
	@echo "Composite Provider Build System"
	@echo "Available targets:"
	@echo "  all      - Build the provider library (default)"
	@echo "  clean    - Remove built files"
	@echo "  test     - Build and run tests"
	@echo "  install  - Install the provider"
	@echo "  help     - Show this help message"
