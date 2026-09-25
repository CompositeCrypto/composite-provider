#include <stdio.h>
#include <string.h>

#include <openssl/encoder.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "composite_test.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
        goto done; \
    } \
} while (0)

static int test_private_key_info(EVP_PKEY *key, const char *algorithm)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    PKCS8_PRIV_KEY_INFO *info = NULL, *pem_info = NULL, *evp_info = NULL;
    EVP_PKEY *decoded = NULL;
    BIO *pem = NULL;
    unsigned char *der = NULL, *pem_der = NULL, *evp_der = NULL;
    const unsigned char *cursor;
    const ASN1_OBJECT *oid = NULL;
    const X509_ALGOR *algor = NULL;
    size_t der_len = 0;
    int pem_len = 0, evp_len = 0, parameter_type = 0, ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
                                           "DER", "PrivateKeyInfo",
                                           "provider=composite");
    CHECK(encoder != NULL);
    CHECK(OSSL_ENCODER_to_data(encoder, &der, &der_len) == 1);
    cursor = der;
    info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, (long)der_len);
    CHECK(info != NULL && cursor == der + der_len);
    CHECK(PKCS8_pkey_get0(&oid, NULL, NULL, &algor, info) == 1);
    CHECK(OBJ_obj2nid(oid) == OBJ_sn2nid(algorithm));
    X509_ALGOR_get0(NULL, &parameter_type, NULL, algor);
    CHECK(parameter_type == V_ASN1_UNDEF);

    decoded = EVP_PKCS82PKEY(info);
    CHECK(decoded != NULL && EVP_PKEY_eq(key, decoded) == 1);
    CHECK(EVP_PKEY_is_a(decoded, algorithm));

    /* PEM and DER must contain the same PrivateKeyInfo, not extra wrapping. */
    pem = BIO_new(BIO_s_mem());
    CHECK(pem != NULL && PEM_write_bio_PrivateKey(pem, key, NULL, NULL, 0, NULL, NULL) == 1);
    pem_info = PEM_read_bio_PKCS8_PRIV_KEY_INFO(pem, NULL, NULL, NULL);
    CHECK(pem_info != NULL);
    pem_len = i2d_PKCS8_PRIV_KEY_INFO(pem_info, &pem_der);
    CHECK(pem_len > 0 && (size_t)pem_len == der_len);
    CHECK(memcmp(pem_der, der, der_len) == 0);

    /* This API fetches the DER encoder internally and is used by PKCS#12. */
    evp_info = EVP_PKEY2PKCS8(key);
    CHECK(evp_info != NULL);
    evp_len = i2d_PKCS8_PRIV_KEY_INFO(evp_info, &evp_der);
    CHECK(evp_len > 0 && (size_t)evp_len == der_len);
    CHECK(memcmp(evp_der, der, der_len) == 0);
    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    OPENSSL_clear_free(evp_der, evp_len > 0 ? (size_t)evp_len : 0);
    OPENSSL_clear_free(pem_der, pem_len > 0 ? (size_t)pem_len : 0);
    OPENSSL_clear_free(der, der_len);
    BIO_free(pem);
    EVP_PKEY_free(decoded);
    PKCS8_PRIV_KEY_INFO_free(evp_info);
    PKCS8_PRIV_KEY_INFO_free(pem_info);
    PKCS8_PRIV_KEY_INFO_free(info);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

static int test_pkcs12(EVP_PKEY *key)
{
    X509 *certificate = NULL, *recovered_certificate = NULL;
    X509_NAME *subject;
    EVP_PKEY *recovered = NULL;
    PKCS12 *pfx = NULL, *decoded = NULL;
    unsigned char *der = NULL;
    const unsigned char *cursor;
    const char *password = "composite-regression-test";
    int der_len = 0, ok = 0;

    certificate = X509_new();
    CHECK(certificate != NULL);
    CHECK(X509_set_version(certificate, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate), -60) != NULL);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) != NULL);
    subject = X509_get_subject_name(certificate);
    CHECK(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"PKCS12 round trip",
                                    -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(certificate, subject) == 1);
    CHECK(X509_set_pubkey(certificate, key) == 1);
    CHECK(X509_sign(certificate, key, NULL) > 0);

    pfx = PKCS12_create(password, "composite key", key, certificate, NULL,
                        NID_aes_256_cbc, NID_aes_256_cbc, 0, 0, 0);
    CHECK(pfx != NULL);
    der_len = i2d_PKCS12(pfx, &der);
    CHECK(der_len > 0);
    cursor = der;
    decoded = d2i_PKCS12(NULL, &cursor, der_len);
    CHECK(decoded != NULL && cursor == der + der_len);
    CHECK(PKCS12_verify_mac(decoded, "wrong-password", -1) == 0);
    ERR_clear_error();
    CHECK(PKCS12_parse(decoded, password, &recovered, &recovered_certificate, NULL) == 1);
    CHECK(recovered != NULL && EVP_PKEY_eq(key, recovered) == 1);
    CHECK(recovered_certificate != NULL && X509_cmp(certificate, recovered_certificate) == 0);
    CHECK(X509_verify(recovered_certificate, key) == 1);
    CHECK(X509_sign(certificate, recovered, NULL) > 0);
    CHECK(X509_verify(certificate, key) == 1);
    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    OPENSSL_clear_free(der, der_len > 0 ? (size_t)der_len : 0);
    PKCS12_free(decoded);
    PKCS12_free(pfx);
    EVP_PKEY_free(recovered);
    X509_free(recovered_certificate);
    X509_free(certificate);
    return ok;
}

int main(void)
{
    const char *algorithms[] = {
        MLDSA44_RSA2048_PSS_SN, MLDSA44_RSA2048_PKCS15_SN,
        MLDSA44_ED25519_SN, MLDSA44_P256_SN,
        MLDSA65_RSA3072_PSS_SN, MLDSA65_RSA3072_PKCS15_SN,
        MLDSA65_RSA4096_PSS_SN, MLDSA65_RSA4096_PKCS15_SN,
        MLDSA65_P256_SN, MLDSA65_P384_SN, MLDSA65_BRAINPOOLP256_SN,
        MLDSA65_ED25519_SN, MLDSA87_P384_SN, MLDSA87_BRAINPOOLP384_SN,
        MLDSA87_ED448_SN, MLDSA87_RSA3072_PSS_SN,
        MLDSA87_RSA4096_PSS_SN, MLDSA87_P521_SN
    };
    COMPOSITE_TEST_PROVIDERS providers = { NULL, NULL };
    size_t i;
    int ok = 1;

    if (!composite_test_providers_load(&providers)) {
        composite_test_providers_unload(&providers);
        return 1;
    }
    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithms[i],
                                                      "provider=composite");
        EVP_PKEY *key = NULL;
        int passed = ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0
                     && EVP_PKEY_generate(ctx, &key) > 0;

        if (passed)
            passed = test_private_key_info(key, algorithms[i]) && test_pkcs12(key);
        printf("%s: %s\n", algorithms[i], passed ? "PASS" : "FAIL");
        if (!passed)
            ERR_print_errors_fp(stderr);
        ok &= passed;
        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(ctx);
    }
    composite_test_providers_unload(&providers);
    return ok ? 0 : 1;
}
