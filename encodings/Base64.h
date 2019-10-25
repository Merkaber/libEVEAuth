/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "../shared.h"

namespace EVEAuth {
    class Base64 {
    public:
        explicit Base64(const std::string &str);
        ~Base64();

        std::string encode();
        std::string decode();

    private:
        static constexpr std::array<char, 64> base64Chars = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        };

        static constexpr char base64Fill = '=';

        static constexpr std::array<char, 2> base64UrlSafeChars = {'-', '_'};

        const std::string base64UrlSafeFill = "%3d";
    };
}
