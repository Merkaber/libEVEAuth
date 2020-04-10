/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#define WIN

#define LIBRARY_NAME "EVEAuth: "

/* Global includes */
#include <string>
#include <array>
#include <utility>
#include <vector>
#include <sstream>

#ifdef WIN
#include <winsock2.h>
#include <windows.h>
#endif

namespace EVEAuth {
    std::string make_err_msg(std::initializer_list<std::string> list) noexcept
    {
        std::stringstream ss;
        for (auto& s : list) {
            ss << s;
        }
        return ss.str();
    }
}