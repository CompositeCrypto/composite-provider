# Examples

This directory contains example programs demonstrating how to use the Composite Provider.

## Building All Examples

```bash
make
```

## Example 1: Loading the Provider

The `load_provider.c` example demonstrates:
- How to load the composite provider
- How to query provider parameters
- How to list available algorithms

### Building

```bash
gcc -o load_provider load_provider.c -lcrypto
```

### Running

```bash
./load_provider
```

## Example 2: Encoding/Decoding Composite Structures

The `encoding_example.c` example demonstrates:
- Encoding and decoding composite keys
- Encoding and decoding composite signatures with ASN.1
- Encoding and decoding KEM ciphertexts
- Proper memory management with the encoding APIs

### Building

```bash
gcc -I../src -o encoding_example encoding_example.c ../src/composite_encoding.o -lcrypto
```

Or use the Makefile:

```bash
make encoding_example
```

### Running

```bash
./encoding_example
```

### Features Demonstrated

1. **Composite Key Encoding**:
   - Length-prefixed binary format
   - Query mode to determine buffer size
   - Encoding and decoding round-trip

2. **Composite Signature Encoding**:
   - ASN.1 DER encoding for interoperability
   - Standards-compliant format
   - Proper ASN.1 SEQUENCE structure

3. **KEM Ciphertext Encoding**:
   - Efficient binary format
   - Simple length-prefixed encoding
   - Round-trip verification

## Future Examples

Additional examples will be added for:
- Using ML-DSA composite signatures
- Using ML-KEM composite key encapsulation
- Key generation for composite algorithms
- End-to-end encryption with composite algorithms
