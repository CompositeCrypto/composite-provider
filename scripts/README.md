# scripts

Helper scripts for building, testing, and interoperability verification of the
composite provider.

---

## build_and_test.sh

Clones and builds OpenSSL from source if it is not already present, builds the
composite provider, and then delegates to `run_tests.sh` for the full test suite.

**Usage**

```bash
./scripts/build_and_test.sh          # build everything, then run tests
./scripts/build_and_test.sh -f       # soft-clean: remove _build/ before rebuilding
./scripts/build_and_test.sh -F       # hard-clean: remove _build/ and openssl/ before rebuilding
```

**Environment variables**

| Variable         | Default    | Description                                              |
|------------------|------------|----------------------------------------------------------|
| `OPENSSL_BRANCH` | `master`   | Branch or tag to clone from `github.com/openssl/openssl` |
| `MAKE_PARAMS`    | _(empty)_  | Extra flags for every `make` call, e.g. `-j$(nproc)`    |
| `CMAKE_PARAMS`   | _(empty)_  | Extra flags for `cmake`                                  |
| `OSSL_CONFIG`    | _(empty)_  | Extra flags passed to OpenSSL's `./config`               |

**Prerequisites:** `git`, `cmake`, `make`, a C compiler, and `zip`.

---

## run_tests.sh

Runs the compiled unit-test binaries for the composite provider.  Can be invoked
on its own once the provider has been built, or is called automatically by
`build_and_test.sh`.

**Usage**

```bash
# Run all tests (defaults: openssl/ and _build/ under the project root)
./scripts/run_tests.sh

# Run a specific subset
TESTS="test_sign_verify test_oid_registration" ./scripts/run_tests.sh

# Point at a custom build or library location
BUILD_DIR=/tmp/my_build OSSL_LIB_DIR=/opt/openssl/lib ./scripts/run_tests.sh
```

**Environment variables**

| Variable      | Default              | Description                              |
|---------------|----------------------|------------------------------------------|
| `OSSL_LIB_DIR`| `<root>/openssl`     | Directory containing `libcrypto.so*`     |
| `BUILD_DIR`   | `<root>/_build`      | Provider build directory (contains `composite.so` and `tests/`) |
| `TESTS`       | _(all tests)_        | Space-separated list of test binary names to run |

**Tests run** (in order):

| Binary                 | What it covers                                                  |
|------------------------|-----------------------------------------------------------------|
| `test_provider`        | Provider load, name/version params, KEM algorithm availability  |
| `test_encoding`        | Public/private key encode–decode round-trips, KEM wire format   |
| `test_keygen_sig`      | `composite_signkey_generate` for all 18 algorithms              |
| `test_evp_keygen`      | Same via `COMPOSITE_PROVIDER_CTX_new` helper                    |
| `test_sign_verify`     | Sign+verify round-trips, M' context string, tamper detection    |
| `test_oid_registration`| OID registration, `OBJ_find_sigid_algs`, idempotency            |

---

## gen_composite_r5.sh

Generates an `artifacts_certs_r5.zip` containing self-signed TA certificates
and PKCS#8 private keys for all 18 composite signature algorithms, following the
[IETF Hackathon pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates) R5 artifact naming convention:

```
<friendly>-<oid>_ta.der    (DER self-signed CA certificate, 10-year)
<friendly>-<oid>_priv.der  (DER PKCS#8 private key)
```

**Usage**

```bash
./scripts/gen_composite_r5.sh               # writes zip to scripts/
./scripts/gen_composite_r5.sh /output/dir   # writes zip to the given directory
```

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |

**Prerequisites:** The composite provider must already be built (`_build/composite.so`
must exist).  Run `build_and_test.sh` first.

---

## check_composite_r5.sh

Verifies an `artifacts_certs_r5/` directory of R5 artifacts against the
composite provider for all 18 algorithms.  Two checks are performed per
algorithm:

- **CERT** — self-signed TA certificate is correctly verified with `-check_ss_sig`.
- **PRIVKEY** — sign test data with the private key and verify the signature
  against the public key extracted from the TA cert.

**Usage**

```bash
./scripts/check_composite_r5.sh                        # looks in <root>/test/artifacts_certs_r5/
./scripts/check_composite_r5.sh /path/to/artifacts_dir
```

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |
| `OPENSSL_MODULES` | `<root>/_build`             | Directory containing `composite.so` |

**Prerequisites:** The composite provider must already be built.  The artifacts
directory must contain files named `*<oid>_ta.der` and `*<oid>_priv.der`.

---

## run_all_providers.sh

Iterates over every provider directory found under `scripts/providers/`, extracts
its `artifacts_certs_r5.zip`, runs `check_composite_r5.sh` against the composite
provider, generates per-provider CSV compatibility matrices, and writes a full
report to `scripts/output.txt`.

**Usage**

```bash
./scripts/run_all_providers.sh             # verify all providers, no CSV output
./scripts/run_all_providers.sh --compat    # also generate compatibility matrix CSVs
```

**Required preparation**

1. Clone the IETF Hackathon PQC Certificates repository:

   ```bash
   git clone https://github.com/IETF-Hackathon/pqc-certificates.git
   ```

2. Copy (or symlink) the provider subdirectories from that repo into
   `scripts/providers/`.  Each provider must contain an `artifacts_certs_r5.zip`:

   ```
   scripts/
   └── providers/
       ├── provider_name1/
       │   └── artifacts_certs_r5.zip
       ├── provider_name2/
       │   └── artifacts_certs_r5.zip
       └── ...
   ```

   The expected layout mirrors `pqc-certificates/providers/<name>/artifacts_certs_r5.zip`.

3. The composite provider must already be built (`_build/composite.so`).

**Output**

- `scripts/output.txt` — full per-provider verification log (always written).
- `scripts/compatMatrices/artifacts_certs_r5/<provider>_composite-crypto.csv` —
  compatibility matrix CSV per provider (`Y`/`N` per OID × {cert, priv}).
  Only generated when `-compat` is passed.

  This format follows the convention used by the
  [IETF Hackathon pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
  repository, where each participating implementation submits a compatibility matrix
  to record cross-provider interoperability results.  A `Y` indicates that the
  composite provider successfully verified the artifact generated by the other
  provider; `N` indicates a failure.

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |
| `OPENSSL_MODULES` | `<root>/_build`             | Directory containing `composite.so` |
