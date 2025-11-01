#include <stdio.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/*
 * Example: Loading the Composite Provider
 * 
 * This example demonstrates how to:
 * 1. Load the composite provider
 * 2. Query provider information
 * 3. Work with composite algorithms
 */

int main(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_PARAM params[5];
    char *name = NULL;
    char *version = NULL;
    char *buildinfo = NULL;
    int status = 0;

    printf("Composite Provider Example\n");
    printf("==========================\n\n");

    /* Load the provider */
    printf("Loading composite provider...\n");
    
    /* Try to set the module path to current directory first */
    OSSL_PROVIDER_set_default_search_path(NULL, ".");
    prov = OSSL_PROVIDER_load(NULL, "composite");
    
    if (prov == NULL) {
        printf("ERROR: Failed to load composite provider\n");
        printf("Make sure the provider is:\n");
        printf("  1. Built (run 'make' in the repository root)\n");
        printf("  2. Either installed in OpenSSL modules directory, or\n");
        printf("  3. Available in the current directory as composite.so\n");
        return 1;
    }
    printf("SUCCESS: Provider loaded\n\n");

    /* Query provider parameters */
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, 0);
    params[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &buildinfo, 0);
    params[3] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &status);
    params[4] = OSSL_PARAM_construct_end();

    if (OSSL_PROVIDER_get_params(prov, params)) {
        printf("Provider Information:\n");
        printf("  Name:      %s\n", name ? name : "unknown");
        printf("  Version:   %s\n", version ? version : "unknown");
        printf("  Build:     %s\n", buildinfo ? buildinfo : "unknown");
        printf("  Status:    %s\n\n", status ? "active" : "inactive");
    }

    /* Display available algorithms */
    printf("Available ML-DSA Composite Signature Algorithms:\n");
    printf("  1. ML-DSA-44-RSA2048      - ML-DSA-44 with RSA-2048\n");
    printf("  2. ML-DSA-44-ECDSA-P256   - ML-DSA-44 with ECDSA P-256\n");
    printf("  3. ML-DSA-65-RSA3072      - ML-DSA-65 with RSA-3072\n");
    printf("  4. ML-DSA-65-ECDSA-P384   - ML-DSA-65 with ECDSA P-384\n");
    printf("  5. ML-DSA-87-RSA4096      - ML-DSA-87 with RSA-4096\n");
    printf("  6. ML-DSA-87-ECDSA-P521   - ML-DSA-87 with ECDSA P-521\n\n");

    printf("Available ML-KEM Composite KEM Algorithms:\n");
    printf("  1. ML-KEM-512-ECDH-P256   - ML-KEM-512 with ECDH P-256\n");
    printf("  2. ML-KEM-768-ECDH-P384   - ML-KEM-768 with ECDH P-384\n");
    printf("  3. ML-KEM-1024-ECDH-P521  - ML-KEM-1024 with ECDH P-521\n\n");

    printf("Usage Notes:\n");
    printf("  - Composite algorithms provide hybrid security\n");
    printf("  - Both PQ and traditional components must be compromised to break security\n");
    printf("  - Ideal for transition to post-quantum cryptography\n\n");

    /* Unload the provider */
    OSSL_PROVIDER_unload(prov);
    printf("Provider unloaded successfully.\n");

    return 0;
}
