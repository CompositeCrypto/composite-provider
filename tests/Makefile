# Test Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../include
LDFLAGS = -lcrypto

TEST_SOURCES = test_provider.c
TEST_TARGET = test_provider

.PHONY: all clean test

all: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TEST_TARGET)
