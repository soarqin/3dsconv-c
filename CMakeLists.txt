cmake_minimum_required(VERSION 3.2)

project(3dsconv_c)

set(SOURCE_FILES
        mbedtls/aes.c
        mbedtls/aes.h
        mbedtls/aesni.c
        mbedtls/aesni.h
        mbedtls/padlock.c
        mbedtls/padlock.h
        mbedtls/sha256.c
        mbedtls/sha256.h
        3ds/3dsconv.c
        3ds/3dsconv.h
        3ds/bn.c
        3ds/bn.h
        3ds/cia.c
        3ds/cia.h
        3ds/ncch.c
        3ds/ncch.h
        3ds/ncsd.c
        3ds/ncsd.h
        3ds/ticket.h
        3ds/tmd.h
        main.c)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
foreach(fn_ ${SOURCE_FILES})
  get_filename_component(fd_ ${fn_} DIRECTORY)
  if(fd_)
    string(REPLACE "/" "\\" fd2_ "${fd_}")
    source_group("\\${fd2_}" FILES "${fn_}")
  else()
    source_group("\\" FILES "${fn_}")
  endif()
endforeach()

add_executable(3dsconv ${SOURCE_FILES})
target_include_directories(3dsconv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(3dsconv PRIVATE "-DMBEDTLS_HAVE_ASM")
