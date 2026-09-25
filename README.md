# Composite Provider

A clean implementation of an OpenSSL provider that implements the ML-DSA and ML-KEM composite standards.

## Overview

This OpenSSL provider implements composite cryptographic algorithms that combine post-quantum algorithms (ML-DSA and ML-KEM) with traditional cryptographic algorithms to provide hybrid security. This approach ensures security both against current threats and future quantum computing threats.

### Supported Algorithms

#### ML-DSA Composite Signatures
Module-Lattice-Based Digital Signature Algorithm (ML-DSA, formerly Dilithium) combined with traditional signature algorithms:

- **ML-DSA-44-RSA2048**: ML-DSA-44 + RSA-2048
- **ML-DSA-44-ECDSA-P256**: ML-DSA-44 + ECDSA with P-256 curve
- **ML-DSA-65-RSA3072**: ML-DSA-65 + RSA-3072
- **ML-DSA-65-ECDSA-P384**: ML-DSA-65 + ECDSA with P-384 curve
- **ML-DSA-87-RSA4096**: ML-DSA-87 + RSA-4096
- **ML-DSA-87-ECDSA-P521**: ML-DSA-87 + ECDSA with P-521 curve

Composite signature keys support unencrypted PKCS#8 `PrivateKeyInfo` export
in PEM and DER. DER encoding also enables `EVP_PKEY2PKCS8` and encrypted
PKCS#12 creation through `PKCS12_create`. The `test_sig_pkcs8` regression test
checks key and certificate round trips for all 18 signature algorithms.

#### ML-KEM Composite Key Encapsulation
Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM, formerly Kyber)
combined with RSA-OAEP, ECDH, X25519 or X448 — the 12 algorithms of
draft-ietf-lamps-pq-composite-kem-18:

- **id-MLKEM768-RSA2048-SHA3-256**, **id-MLKEM768-RSA3072-SHA3-256**,
  **id-MLKEM768-RSA4096-SHA3-256**
- **id-MLKEM768-X25519-SHA3-256**
- **id-MLKEM768-ECDH-P256-SHA3-256**, **id-MLKEM768-ECDH-P384-SHA3-256**,
  **id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256**
- **id-MLKEM1024-RSA3072-SHA3-256**
- **id-MLKEM1024-ECDH-P384-SHA3-256**, **id-MLKEM1024-ECDH-P521-SHA3-256**,
  **id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256**
- **id-MLKEM1024-X448-SHA3-256**

Key generation, encapsulation, decapsulation, and PKCS#8 /
SubjectPublicKeyInfo key loading and export (PEM and DER) are implemented;
decapsulation is verified against the LAMPS working group's Appendix G test
vectors for all 12 algorithms.

## Requirements

- OpenSSL 3.5 or later (ML-KEM and ML-DSA are 3.5 features)
- CMake 3.10 or later (or GNU Make)
- GCC or compatible C compiler

## Building

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

### Using Make

```bash
make
```

## Installation

### Using CMake

```bash
cd build
sudo make install
```

### Using Make

```bash
sudo make install
```

The provider will be installed to the OpenSSL modules directory (typically `/usr/lib/ossl-modules/`).

## Testing

### Using CMake

```bash
cd build
ctest
```

### Using Make

```bash
make test
```

## Usage

### Loading the Provider

To use the composite provider in your OpenSSL application:

```c
#include <openssl/provider.h>

OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "composite");
if (prov == NULL) {
    /* Handle error */
}

/* Use composite algorithms */

OSSL_PROVIDER_unload(prov);
```

### Configuration File

You can also configure OpenSSL to automatically load the provider by adding to your `openssl.cnf`:

```ini
[openssl_init]
providers = provider_sect

[provider_sect]
composite = composite_sect
default = default_sect

[composite_sect]
activate = 1
```

## Architecture

The provider implements:

1. **Provider Infrastructure** (`src/common/provider.c`): Core provider initialization and registration
2. **Signature Operations** (`src/signature/composite_sig.c`): Composite signature implementation
3. **KEM Operations** (`src/kem/composite_kem.c`): Composite KEM implementation
4. **ML-DSA Dispatch** (`src/signature/mldsa_composite.c`): ML-DSA algorithm dispatch tables
5. **ML-KEM Dispatch** (`src/kem/mlkem_composite.c`): ML-KEM algorithm dispatch tables

## Security Considerations

Composite algorithms provide security by combining:
- **Post-quantum security** from ML-DSA and ML-KEM
- **Traditional security** from RSA, ECDSA, and ECDH

Both components must be compromised for the composite scheme to fail, providing defense-in-depth against both current and future threats.

## Standards Compliance

This implementation follows the NIST post-quantum cryptography standardization process:
- ML-DSA (FIPS 204): Module-Lattice-Based Digital Signature Standard
- ML-KEM (FIPS 203): Module-Lattice-Based Key-Encapsulation Mechanism Standard

Composite schemes follow the principles outlined in various IETF drafts and academic papers on hybrid post-quantum cryptography.

## License

Apache License 2.0 - See LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure all code follows the existing style and includes appropriate tests.

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [OpenSSL Provider API](https://www.openssl.org/docs/man3.0/man7/provider.html)
