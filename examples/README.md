# Examples

This directory contains example programs demonstrating how to use the Composite Provider.

## Example: Loading the Provider

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

## Future Examples

Additional examples will be added for:
- Using ML-DSA composite signatures
- Using ML-KEM composite key encapsulation
- Key generation for composite algorithms
- End-to-end encryption with composite algorithms
