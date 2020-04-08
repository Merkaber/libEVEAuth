cmake_minimum_required(VERSION 3.15)
project(EVEAuth)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(EVEAuth VERSION 1.0.0)

if(WIN32)
    add_definitions(-DCURL_STATICLIB)
endif(WIN32)

set(SRC_FILES encodings/Base64.cpp encodings/Base64.h shared.h Auth.cpp Auth.h Token.cpp Token.h utils/picojson.h utils/jwt.h utils/CallBackTimer.cpp utils/CallBackTimer.h)

find_package(CURL REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} curl OpenSSL::Crypto Threads::Threads dl)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} curl OpenSSL::Crypto Threads::Threads dl wldap32 ws2_32)
endif(WIN32)