cmake_minimum_required(VERSION 3.10)
project(composite_provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Find OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(PROVIDER_SOURCES
    src/provider.c
    src/provider_ctx.c
    src/composite_sig.c
    src/composite_sig_key.c
    src/composite_sig_encoding.c
    src/composite_encoder.c
    src/composite_kem_key.c
    src/composite_kem_keymgmt.c
    src/composite_kem_encoding.c
    src/mldsa_composite.c
    src/composite_keys.c
    src/composite_keymgmt.c
    src/composite_decoder.c
)

# Build shared library
add_library(composite SHARED ${PROVIDER_SOURCES})
target_link_libraries(composite ${OPENSSL_CRYPTO_LIBRARY})

# Set output properties
set_target_properties(composite PROPERTIES
    PREFIX ""
    OUTPUT_NAME "composite"
)
if(APPLE)
    set_target_properties(composite PROPERTIES
        SUFFIX ".dylib"
    )
else()
    set_target_properties(composite PROPERTIES
        SUFFIX ".so"
    )
endif()

# Installation
install(TARGETS composite DESTINATION lib)

# Tests
enable_testing()
add_subdirectory(tests)
