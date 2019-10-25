cmake_minimum_required(VERSION 3.15)
project(EVEAuth)

set(CMAKE_CXX_STANDARD 17)

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
link_directories(${CURL_LIBRARIES})

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})

set(SRC_FILES encodings/Encoding.cpp encodings/Encoding.h shared.h)

add_library(${CMAKE_PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${CMAKE_PROJECT_NAME} curl)