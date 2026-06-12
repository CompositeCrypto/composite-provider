cmake_minimum_required(VERSION 3.10)

set(PROVIDER_SRC ${CMAKE_SOURCE_DIR}/src)

# Provider smoke-test
add_executable(test_provider test_provider.c)
target_link_libraries(test_provider ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME provider_test COMMAND test_provider)

# Encoding round-trip tests (sig + KEM)
add_executable(test_encoding
    test_encoding.c
    ${PROVIDER_SRC}/composite_sig_encoding.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/composite_kem_encoding.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_include_directories(test_encoding PRIVATE ${PROVIDER_SRC})
target_link_libraries(test_encoding ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_encoding COMMAND test_encoding)

# Key-generation tests — manual COMPOSITE_CTX allocation
add_executable(test_keygen_sig
    test_keygen_sig.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_include_directories(test_keygen_sig PRIVATE ${PROVIDER_SRC})
target_link_libraries(test_keygen_sig ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_keygen_sig COMMAND test_keygen_sig)

# Key-generation tests — COMPOSITE_PROVIDER_CTX_new helper
add_executable(test_evp_keygen
    test_evp_keygen.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_include_directories(test_evp_keygen PRIVATE ${PROVIDER_SRC})
target_link_libraries(test_evp_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_keygen COMMAND test_evp_keygen)

# Sign / verify internal unit tests
add_executable(test_sign_verify
    test_sign_verify.c
    ${PROVIDER_SRC}/composite_sig.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_include_directories(test_sign_verify PRIVATE ${PROVIDER_SRC})
target_link_libraries(test_sign_verify ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_sign_verify COMMAND test_sign_verify)

# OID registration unit tests
add_executable(test_oid_registration
    test_oid_registration.c
    ${PROVIDER_SRC}/composite_encoder.c
    ${PROVIDER_SRC}/composite_sig_encoding.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_include_directories(test_oid_registration PRIVATE ${PROVIDER_SRC})
target_link_libraries(test_oid_registration ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_oid_registration COMMAND test_oid_registration)