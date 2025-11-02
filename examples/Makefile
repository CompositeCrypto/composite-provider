# Makefile for Examples
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../src
LDFLAGS = -lcrypto

EXAMPLES = load_provider encoding_example

.PHONY: all clean

all: $(EXAMPLES)

load_provider: load_provider.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

encoding_example: encoding_example.c ../src/composite_sig_key.c ../src/composite_sig_encoding.c ../src/composite_kem_key.c ../src/composite_kem_encoding.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXAMPLES)
