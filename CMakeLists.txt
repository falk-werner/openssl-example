# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.20)
project(openssl-example)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto>3.0)

add_executable(sha256 src/sha256.cpp)
target_include_directories(sha256 PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(sha256 PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(sha256 PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(self_signed src/self_signed.cpp)
target_include_directories(self_signed PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(self_signed PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(self_signed PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(create_csr src/create_csr.cpp)
target_include_directories(create_csr PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(create_csr PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(create_csr PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(sign_csr src/sign_csr.cpp)
target_include_directories(sign_csr PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(sign_csr PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(sign_csr PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(create_crl src/create_crl.cpp)
target_include_directories(create_crl PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(create_crl PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(create_crl PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(verify_cert src/verify_cert.cpp)
target_include_directories(verify_cert PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(verify_cert PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(verify_cert PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(cms_sign src/cms_sign.cpp)
target_include_directories(cms_sign PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(cms_sign PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(cms_sign PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(cms_verify src/cms_verify.cpp)
target_include_directories(cms_verify PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(cms_verify PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(cms_verify PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})

add_executable(create_test_pki src/create_test_pki.cpp)
target_include_directories(create_test_pki PRIVATE lib include ${OPENSSL_INCLUDE_DIRS})
target_compile_options(create_test_pki PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(create_test_pki PRIVATE ${LIBCRYPTO_LINK_LIBRARIES})
