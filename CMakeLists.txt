cmake_minimum_required(VERSION 3.15)
project(EVEAuth)

set(CMAKE_CXX_STANDARD 17)

set(SRC_FILES encodings/Base64.cpp encodings/Base64.h shared.h hashings/SHA256.cpp hashings/SHA256.h)

add_library(${CMAKE_PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${CMAKE_PROJECT_NAME})