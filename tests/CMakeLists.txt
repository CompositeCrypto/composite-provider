cmake_minimum_required(VERSION 3.10)

# Test executable
add_executable(test_provider test_provider.c)
target_link_libraries(test_provider ${OPENSSL_CRYPTO_LIBRARY})

# Add test
add_test(NAME provider_test COMMAND test_provider)

# Test Executable
add_executable(test_encoding test_encoding.c)
target_link_libraries(test_encoding ${OPENSSL_CRYPTO_LIBRARY})

# Add test
add_test(NAME test_encoding COMMAND test_encoding)