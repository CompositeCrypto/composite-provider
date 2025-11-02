# Test Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../include -I../src
LDFLAGS = -lcrypto

# Provider object files (need these for encoding tests)
PROVIDER_OBJS = ../src/composite_encoding.o

TEST_SOURCES = test_provider.c test_encoding.c
TEST_TARGETS = test_provider test_encoding

.PHONY: all clean test

all: $(TEST_TARGETS)

test_provider: test_provider.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_encoding: test_encoding.c $(PROVIDER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGETS)
	./test_provider
	./test_encoding

clean:
	rm -f $(TEST_TARGETS)
