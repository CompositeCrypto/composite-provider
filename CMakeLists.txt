cmake_minimum_required(VERSION 3.10)
project(composite_provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Find OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(PROVIDER_SOURCES
    src/provider.c
    src/composite_sig.c
    src/composite_kem.c
    src/mldsa_composite.c
    src/mlkem_composite.c
    src/composite_keys.c
)

# Build shared library
add_library(composite SHARED ${PROVIDER_SOURCES})
target_link_libraries(composite ${OPENSSL_CRYPTO_LIBRARY})

# Set output properties
set_target_properties(composite PROPERTIES
    PREFIX ""
    OUTPUT_NAME "composite"
    SUFFIX ".so"
)

# Installation
install(TARGETS composite DESTINATION lib)

# Tests
enable_testing()
add_subdirectory(tests)
