cmake_minimum_required(VERSION 3.15)

set(DEFAULT_BUILD_TYPE "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Uncomment to install the libraries inside the source directory
#set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})

project(EVEAuth VERSION 1.0.0 DESCRIPTION "A authentication library for the ESI")

add_compile_definitions(LIBRARY_NAME="${PROJECT_NAME}: ")

configure_file("${PROJECT_NAME}.pc.in" "${PROJECT_NAME}.pc" @ONLY)

set(SRC_FILES src/encodings/Base64.cpp src/encodings/Base64.h src/Auth.cpp include/Auth.h src/Token.cpp src/Token.h src/utils/picojson.h
        src/utils/jwt.h src/utils/CallBackTimer.cpp src/utils/CallBackTimer.h)

if(WIN32)
    add_definitions(-DCURL_STATICLIB)
endif(WIN32)
find_package(CURL REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${SRC_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include> PRIVATE src)

target_link_libraries(${PROJECT_NAME} curl OpenSSL::Crypto Threads::Threads dl)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} curl OpenSSL::Crypto Threads::Threads dl wldap32 ws2_32)
endif(WIN32)

install(TARGETS ${PROJECT_NAME} EXPORT EVEAuthConfig
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT EVEAuthConfig DESTINATION share/EVEAuth/cmake)

install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc" DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

export(TARGETS ${PROJECT_NAME} FILE EVEAuthConfig.cmake)