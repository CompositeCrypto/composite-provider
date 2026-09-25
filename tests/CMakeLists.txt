cmake_minimum_required(VERSION 3.10)

set(PROVIDER_COMMON ${CMAKE_SOURCE_DIR}/src/common)
set(PROVIDER_KEM ${CMAKE_SOURCE_DIR}/src/kem)
set(PROVIDER_SIGNATURE ${CMAKE_SOURCE_DIR}/src/signature)

add_executable(test_provider test_provider.c test_helpers.c)
target_include_directories(test_provider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_provider ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME provider_test COMMAND test_provider)

add_executable(test_encoding
    test_encoding.c
    ${PROVIDER_SIGNATURE}/composite_sig_encoding.c
    ${PROVIDER_SIGNATURE}/composite_sig_key.c
    ${PROVIDER_KEM}/composite_kem_encoding.c
    ${PROVIDER_COMMON}/provider_ctx.c
)
target_link_libraries(test_encoding ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_encoding COMMAND test_encoding)

add_executable(test_keygen_sig
    test_keygen_sig.c
    ${PROVIDER_SIGNATURE}/composite_sig_key.c
    ${PROVIDER_COMMON}/provider_ctx.c
)
target_link_libraries(test_keygen_sig ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_keygen_sig COMMAND test_keygen_sig)

add_executable(test_evp_keygen
    test_evp_keygen.c
    ${PROVIDER_SIGNATURE}/composite_sig_key.c
    ${PROVIDER_COMMON}/provider_ctx.c
)
target_link_libraries(test_evp_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_keygen COMMAND test_evp_keygen)

add_executable(test_evp_ecdsa_keygen test_evp_ecdsa_keygen.c)
target_include_directories(test_evp_ecdsa_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_evp_ecdsa_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_dependencies(test_evp_ecdsa_keygen composite)
add_test(NAME test_evp_ecdsa_keygen COMMAND test_evp_ecdsa_keygen)
set_tests_properties(test_evp_ecdsa_keygen PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:composite>"
)

add_executable(test_sign_verify
    test_sign_verify.c
    ${PROVIDER_SIGNATURE}/composite_sig.c
    ${PROVIDER_SIGNATURE}/composite_sig_key.c
    ${PROVIDER_COMMON}/provider_ctx.c
)
target_link_libraries(test_sign_verify ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_sign_verify COMMAND test_sign_verify)

add_executable(test_oid_registration
    test_oid_registration.c
    ${PROVIDER_SIGNATURE}/composite_encoder.c
    ${PROVIDER_SIGNATURE}/composite_sig_encoding.c
    ${PROVIDER_SIGNATURE}/composite_sig_key.c
    ${PROVIDER_KEM}/composite_kem_info.c
    ${PROVIDER_COMMON}/provider_ctx.c
)
target_link_libraries(test_oid_registration ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_oid_registration COMMAND test_oid_registration)

add_executable(test_keygen_kem
    test_keygen_kem.c
    ${PROVIDER_KEM}/composite_kem_key.c
    ${PROVIDER_KEM}/composite_kem_info.c
    ${PROVIDER_KEM}/composite_kem_encoding.c
)
target_link_libraries(test_keygen_kem ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_keygen_kem COMMAND test_keygen_kem)

add_executable(test_kem_combiner_vectors
    test_kem_combiner_vectors.c
    ${PROVIDER_KEM}/composite_kem_info.c
)
target_link_libraries(test_kem_combiner_vectors ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_kem_combiner_vectors COMMAND test_kem_combiner_vectors)

add_executable(test_evp_kem_keygen test_evp_kem_keygen.c)
target_include_directories(test_evp_kem_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_evp_kem_keygen ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_kem_keygen COMMAND test_evp_kem_keygen)

add_executable(test_evp_kem_encaps test_evp_kem_encaps.c)
target_include_directories(test_evp_kem_encaps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_evp_kem_encaps ${OPENSSL_CRYPTO_LIBRARY})
add_test(NAME test_evp_kem_encaps COMMAND test_evp_kem_encaps)

# Composite KEM known-answer tests.
#
# The vector file is not vendored (see tests/data/README.md). When it is
# absent the tests still build and still run -- they report skipped. Making
# them conditional on the file instead would drop them from the suite
# entirely, which looks identical to a suite where every test passes.
set(KEM_VECTOR_JSON ${CMAKE_CURRENT_SOURCE_DIR}/data/composite_kem_testvectors.json)
set(KEM_VECTOR_HEADER ${CMAKE_CURRENT_BINARY_DIR}/composite_kem_test_vectors.h)
set(KEM_VECTOR_TESTS
    test_kem_decaps_vectors
    test_kem_keyload
    test_kem_codec_roundtrip
    test_kem_negative
)

if(EXISTS ${KEM_VECTOR_JSON})
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_custom_command(
        OUTPUT ${KEM_VECTOR_HEADER}
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_kem_vectors.py
                ${KEM_VECTOR_JSON} ${KEM_VECTOR_HEADER}
        DEPENDS ${KEM_VECTOR_JSON}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_kem_vectors.py
        COMMENT "Generating composite KEM test vectors"
    )
    add_custom_target(kem_vectors DEPENDS ${KEM_VECTOR_HEADER})
else()
    message(STATUS
        "composite KEM vectors absent; KEM vector tests will skip "
        "(see tests/data/README.md)")
endif()

foreach(kem_test IN LISTS KEM_VECTOR_TESTS)
    add_executable(${kem_test} ${kem_test}.c)
    target_include_directories(${kem_test}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${kem_test} ${OPENSSL_CRYPTO_LIBRARY})
    if(EXISTS ${KEM_VECTOR_JSON})
        add_dependencies(${kem_test} kem_vectors)
        target_compile_definitions(${kem_test} PRIVATE COMPOSITE_KEM_HAVE_VECTORS)
    endif()
    add_test(NAME ${kem_test} COMMAND ${kem_test})
endforeach()

set_tests_properties(provider_test test_evp_kem_keygen test_evp_kem_encaps
                     ${KEM_VECTOR_TESTS} PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:composite>"
)

# These tests need ML-KEM from the linked OpenSSL (3.5+). Without it they must
# report as skipped: returning 0 would make an unexercised code path look tested.
set_tests_properties(test_evp_kem_keygen test_evp_kem_encaps
                     ${KEM_VECTOR_TESTS} PROPERTIES
    SKIP_RETURN_CODE 77
)
