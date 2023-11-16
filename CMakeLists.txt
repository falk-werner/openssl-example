cmake_minimum_required(VERSION 3.20)
project(openssl-example)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto>3.0)

add_executable(self_signed src/self_signed.cpp)
target_link_libraries(self_signed PRIVATE ${LIBCRYPTO_LIBRARIES})

add_executable(create_csr src/create_csr.cpp)
target_link_libraries(create_csr PRIVATE ${LIBCRYPTO_LIBRARIES})

add_executable(sign_csr src/sign_csr.cpp)
target_link_libraries(sign_csr PRIVATE ${LIBCRYPTO_LIBRARIES})

add_executable(create_crl src/create_crl.cpp)
target_link_libraries(create_crl PRIVATE ${LIBCRYPTO_LIBRARIES})

add_executable(verify_cert src/verify_cert.cpp)
target_link_libraries(verify_cert PRIVATE ${LIBCRYPTO_LIBRARIES})
