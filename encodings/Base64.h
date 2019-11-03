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
        explicit Base64(std::string inputStr) noexcept;
        ~Base64() noexcept;

        std::string encode() noexcept;
        std::string encodeUrlSafe() noexcept;

        std::string decode() noexcept;
        std::string decodeUrlSafe() noexcept;

    private:
        static std::string decode(const std::string &str) noexcept;

    private:
        static constexpr std::array<char, 64> base64Chars = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        inline static const std::string base64Fill = "=";

        static constexpr std::array<char, 4> base64UrlSafeChars = {'+', '-', '/', '_'};

        inline static const std::string base64UrlSafeFill = "%3d";

        const std::string inputStr;
    };
}
