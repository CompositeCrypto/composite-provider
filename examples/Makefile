# Makefile for Examples
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lcrypto

EXAMPLES = load_provider

.PHONY: all clean

all: $(EXAMPLES)

load_provider: load_provider.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(EXAMPLES)
