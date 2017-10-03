cmake_minimum_required(VERSION 3.2)

project(3dsconv_c)

set(SOURCE_FILES
        crypto/aes.c
        crypto/aes.h
        crypto/aesni.c
        crypto/aesni.h
        crypto/base64.c
        crypto/base64.h
        crypto/padlock.c
        crypto/padlock.h
        crypto/sha256.c
        crypto/sha256.h
        3dsconv.c
        data.inl
        uint128.h)

add_executable(3dsconv ${SOURCE_FILES})
target_compile_definitions(3dsconv PRIVATE "-DMBEDTLS_HAVE_ASM")
