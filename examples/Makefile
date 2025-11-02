# Makefile for Examples
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I../src
LDFLAGS = -lcrypto

# Provider object files
PROVIDER_OBJS = ../src/composite_encoding.o

EXAMPLES = load_provider encoding_example

.PHONY: all clean

all: $(EXAMPLES)

load_provider: load_provider.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

encoding_example: encoding_example.c $(PROVIDER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXAMPLES)
