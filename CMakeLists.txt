cmake_minimum_required(VERSION 3.15)
project(EVEAuth)

set(CMAKE_CXX_STANDARD 14)

if(WIN32)
    add_definitions(-DCURL_STATICLIB)
endif(WIN32)

set(SRC_FILES encodings/Base64.cpp encodings/Base64.h shared.h Auth.cpp Auth.h Token.cpp Token.h utils/picojson.h utils/jwt.h)

if(WIN32)
    set(CURL_LIBRARY C:\\Users\\Merkaber\\Documents\\dev\\libraries\\curl-7.69.0-win64-mingw\\lib)
    set(CURL_INCLUDE_DIR C:\\Users\\Merkaber\\Documents\\dev\\libraries\\curl-7.69.0-win64-mingw\\include)
endif(WIN32)
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
link_directories(${CURL_LIBRARIES})

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} curl OpenSSL::Crypto Threads::Threads dl)