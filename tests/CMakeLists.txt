cmake_minimum_required(VERSION 3.10)

set(PROVIDER_SRC ${CMAKE_SOURCE_DIR}/src)

add_executable(test_provider test_provider.c test_helpers.c)
target_include_directories(test_provider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_provider ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME provider_test COMMAND test_provider)

add_executable(test_encoding
    test_encoding.c
    ${PROVIDER_SRC}/composite_sig_encoding.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/composite_kem_encoding.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_link_libraries(test_encoding ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_encoding COMMAND test_encoding)

add_executable(test_keygen_sig
    test_keygen_sig.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_link_libraries(test_keygen_sig ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_keygen_sig COMMAND test_keygen_sig)

add_executable(test_evp_keygen
    test_evp_keygen.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_link_libraries(test_evp_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_keygen COMMAND test_evp_keygen)

add_executable(test_sign_verify
    test_sign_verify.c
    ${PROVIDER_SRC}/composite_sig.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_link_libraries(test_sign_verify ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_sign_verify COMMAND test_sign_verify)

add_executable(test_oid_registration
    test_oid_registration.c
    ${PROVIDER_SRC}/composite_encoder.c
    ${PROVIDER_SRC}/composite_sig_encoding.c
    ${PROVIDER_SRC}/composite_sig_key.c
    ${PROVIDER_SRC}/provider_ctx.c
)
target_link_libraries(test_oid_registration ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_oid_registration COMMAND test_oid_registration)

add_executable(test_keygen_kem
    test_keygen_kem.c
    ${PROVIDER_SRC}/composite_kem_key.c
)
target_link_libraries(test_keygen_kem ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_keygen_kem COMMAND test_keygen_kem)

add_executable(test_evp_kem_keygen test_evp_kem_keygen.c)
target_link_libraries(test_evp_kem_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_kem_keygen COMMAND test_evp_kem_keygen)

set_tests_properties(provider_test test_evp_kem_keygen PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:composite>"
)
