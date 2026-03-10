# Test Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../include -I../src
LDFLAGS = -lcrypto

TEST_SOURCES = test_provider.c
TEST_TARGET = test_provider

ENCODING_TEST_SOURCES = \
	test_encoding.c \
	../src/provider_ctx.c \
	../src/composite_sig_key.c \
	../src/composite_sig_encoding.c \
	../src/composite_kem_key.c \
	../src/composite_kem_encoding.c

ENCODING_TEST_TARGET = test_encoding

SIGKEYGEN_TEST_SOURCES = \
	test_keygen_sig.c \
	../src/provider_ctx.c \
	../src/composite_sig_encoding.c \
	../src/composite_sig_key.c

SIGKEYGEN_TEST_TARGET = test_sig_keygen

EVPKEYGEN_TEST_SOURCES = \
	test_evp_keygen.c \
	../src/provider_ctx.c \
	../src/composite_sig_encoding.c \
	../src/composite_sig_key.c

EVPKEYGEN_TEST_TARGET = test_evp_keygen

.PHONY: all clean test

all: $(TEST_TARGET) $(ENCODING_TEST_TARGET) $(SIGKEYGEN_TEST_TARGET) $(EVPKEYGEN_TEST_TARGET)
$(TEST_TARGET): $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(ENCODING_TEST_TARGET): $(ENCODING_TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SIGKEYGEN_TEST_TARGET): $(SIGKEYGEN_TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(EVPKEYGEN_TEST_TARGET): $(EVPKEYGEN_TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGET) $(ENCODING_TEST_TARGET) $(SIGKEYGEN_TEST_TARGET) $(EVPKEYGEN_TEST_TARGET)
	./$(TEST_TARGET)
	./$(ENCODING_TEST_TARGET)
	./$(SIGKEYGEN_TEST_TARGET)
	./$(EVPKEYGEN_TEST_TARGET)

clean:
	rm -f $(TEST_TARGET) $(ENCODING_TEST_TARGET) $(SIGKEYGEN_TEST_TARGET) $(EVPKEYGEN_TEST_TARGET)