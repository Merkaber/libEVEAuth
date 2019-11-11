/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "../shared.h"

/* Base64 Exception Range from 00010 - 00099 */
#define ERR_TOO_MANY_FILLS "The given string has to many fills!"
#define ERR_TOO_MANY_FILLS_CODE 00010
#define ERR_WRONG_LENGTH "The given string has a wrong length! Maybe not Base64?"
#define ERR_WRONG_LENGTH_CODE 00011
#define ERR_NO_BASE_CHAR_FOUND "No Base64 char for the given char found!"
#define ERR_NO_BASE_CHAR_FOUND_CODE 00012

namespace EVEAuth {
    class Base64Exception : public std::exception {
    public:
        Base64Exception(std::string message, int errorCode);
        const char* what() const noexcept override;
        int getErrorCode() const noexcept;

    private:
        const std::string message;
        const int errorCode;

    };

    class Base64 {
    public:
        explicit Base64(std::string inputStr) noexcept;
        ~Base64() noexcept;

        std::string encode() noexcept;
        std::string encodeUrlSafe() noexcept;

        std::string decode() noexcept;
        std::string decodeUrlSafe() noexcept;

    private:
        std::string decode(const std::string &str) noexcept(false);
        static std::size_t findBaseChar(const char &c) noexcept(false);

    private:
        static constexpr std::array<char, 64> base64Chars = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        const std::string base64Fill = "=";

        static constexpr std::array<char, 4> base64UrlSafeChars = {'+', '-', '/', '_'};

        const std::string base64UrlSafeFill = "%3d";

        const std::string inputStr;
    };
}
