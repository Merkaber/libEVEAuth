cmake_minimum_required(VERSION 3.15)
project(EVEAuth)

set(CMAKE_CXX_STANDARD 14)

set(SRC_FILES encodings/Base64.cpp encodings/Base64.h shared.h Auth.cpp Auth.h)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto Threads::Threads dl)