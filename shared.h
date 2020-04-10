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

    std::vector<std::string> split_by_delimiter(std::string& s, const std::string& d) noexcept
    {
        std::vector<std::string> vec;
        size_t pos = 0;
        std::string token;
        while ((pos = s.find(d)) != std::string::npos) {
            token = s.substr(0, pos);
            vec.push_back(token);
            s.erase(0, pos + d.length());
        }
        vec.push_back(s);

        return vec;
    }
}