# Test Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../include -I../src
LDFLAGS = -lcrypto

TEST_SOURCES = test_provider.c
TEST_TARGET = test_provider
ENCODING_TEST_TARGET = test_encoding

.PHONY: all clean test

all: $(TEST_TARGET) $(ENCODING_TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(ENCODING_TEST_TARGET): test_encoding.c ../src/composite_sig_key.c ../src/composite_sig_encoding.c ../src/composite_kem_key.c ../src/composite_kem_encoding.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGET) $(ENCODING_TEST_TARGET)
	./$(TEST_TARGET)
	./$(ENCODING_TEST_TARGET)

clean:
	rm -f $(TEST_TARGET) $(ENCODING_TEST_TARGET)
