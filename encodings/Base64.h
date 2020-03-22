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

    /**
     * Exception class for decoding and encoding Base64
     *
     * The exception thrown will always have an unique exception code
     */
    class Base64Exception : public std::exception {
    public:

        /**
         * This constructor expects the error message and the related error code
         * @param message The message which will be available when calling what()
         * @param errorCode The unique error code which will be available when calling getErrorCode()
         */
        Base64Exception(std::string message, int errorCode);

        /**
         * Returns the error message as c-string which has been set when the exception was thrown
         * @return The error message which specifies what kind of exception has been thrown
         */
        const char* what() const noexcept override;

        /**
         * Returns the error code which has been set when the exception was thrown
         * @return The unique error code which specifies what kind of exception has been thrown
         */
        int get_error_code() const noexcept;

    private:

        /* The error message which will be set when the Base64Exception is thrown */
        const std::string message;

        /* The unique error code which will be set when the Base64Exception is thrown */
        const int error_code;
    };

    /**
     * Base64 class for encoding and decoding Base64
     * Specification: https://tools.ietf.org/html/rfc4648
     *
     * In order to encode or decode strings, create and Base64 object and call the
     * corresponding functions on this object
     */
    class Base64 {
    public:

        /**
         * This constructor expects the input string which then will be encoded or decoded
         * @param inputStr The input string which then will be encoded or decoded
         */
        explicit Base64(std::string inputStr) noexcept;

        /**
         * Default destructor
         */
        ~Base64() noexcept;

        /**
         * Encodes the input string which has been set when the Base64 object was created into Base64
         * @return The Base64 encoded input string
         */
        std::string encode() noexcept;

        /**
         * Encodes the input string which has been set when the Base64 object was created into Base64Url
         * @return The Base64Url encoded input string
         */
        std::string encode_url_safe() noexcept;

        /**
         * Decodes the Base64 input string which has been set when the Base64 object was created back into a string
         * @return The decoded Base64 input string
         */
        std::string decode() noexcept;

        /**
         * Decodes the Base64Url input string which has been set when the Base64 object was created back into a string
         * @return The decoded Base64Url input string
         */
        std::string decode_url_safe() noexcept;

    private:

        /**
         * This function does the actual decoding
         *
         * The decode function one is calling on this object will call this function
         *
         * If decodeBase64UrlSafe has been called, the base64_url_safe_fill will be replaced by the standard Base64Fill
         *
         * May throws a Base64Exception if the input string has too many fills or the wrong length
         *
         * @param str The input string of this object or a copy with replaced Base64UrlSafeFill
         * @return The decoded input string
         */
        std::string decode(const std::string &str) noexcept(false);

        /**
         * Finds the corresponding integer value of the given character
         *
         * May throws a Base64Exception when no value has been found!
         *
         * @param c The Base64 character we are looking for
         * @return The corresponding integer value of the given Base64 character
         */
        static std::size_t find_base_char(const char &c) noexcept(false);

    private:

        /* The standard Base64 characters */
        static constexpr std::array<char, 64> base64_chars = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        /* The standard base64_fill */
        const std::string base64_fill = "=";

        /* Array for converting standard Base64 into Base64Url */
        static constexpr std::array<char, 4> base64_url_safe_chars = {'+', '-', '/', '_'};

        /* The standard base64UrlFill */
        const std::string base64_url_safe_fill = "%3d";

        /* The input string which has been set when the Base64 object was created */
        const std::string input_str;
    };
}
