/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Base64.h"
#include <algorithm>

constexpr std::array<char, 64> EVEAuth::Base64::base64_chars;
constexpr std::array<char, 4> EVEAuth::Base64::base64_url_safe_chars;

EVEAuth::Base64Exception::Base64Exception(std::string message, const int errorCode) : message(std::move(message)), error_code(errorCode)
{

}

const char* EVEAuth::Base64Exception::what() const noexcept
{
    return message.c_str();
}

int EVEAuth::Base64Exception::get_error_code() const noexcept
{
    return error_code;
}

EVEAuth::Base64::Base64(std::string inputStr) noexcept : input_str(std::move(inputStr))
{

}

std::string EVEAuth::Base64::encode() noexcept
{
    std::size_t input_size = input_str.size();

    /* Input_size mod 3, since 3 characters (byte) becoming 4 characters */
    uint8_t remainder = input_size % 3u;

    /* Get the input_size without remainder */
    size_t diff_size = input_size - remainder;
    std::stringstream ss;

    /* Do for the first 3*n characters */
    for (std::size_t i = 0; i < diff_size;) {

        /* Get the 3 bytes and save each of them into 32 bit */
        uint32_t b_1 = (unsigned char) input_str[i];
        uint32_t b_2 = (unsigned char) input_str[i + 1];
        uint32_t b_3 = (unsigned char) input_str[i + 2];

        /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxxx yyyyyyyy zzzzzzzz */
        uint32_t combined = (b_1 << 16u) + (b_2 << 8u) + b_3;

        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64_chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64_chars[(combined >> 2u * 6u) & 63u];
        /* Shift the z for 6 spots to the right, e.g. 00000000 00000000 00000000 00yyyyzz*/
        ss << base64_chars[(combined >> 6u) & 63u];
        /* Get the last z's, e.g. 00000000 00000000 00000000 00zzzzzz */
        ss << base64_chars[(combined) & 63u];

        i += 3;
    }

    /* Return the string if there was no remainder */
    if (remainder == 0u) {
        return ss.str();
    }

    std::vector<uint32_t> padding_array;
    /* Save the remaining characters into padding_array */
    for (uint8_t i = 0u; i < 2u; ++i) {
        if (diff_size < input_size) {
            padding_array.push_back((unsigned char) input_str[diff_size]);
            diff_size++;
        } else {
            /* Save 0 if there was only one remaining character */
            padding_array.push_back(0u);
        }
    }

    /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxxx yyyyyyyy 00000000 */
    uint32_t combined = (padding_array.at(0) << 16u) + (padding_array.at(1) << 8u);

    if (remainder == 1u) {
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64_chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64_chars[(combined >> 2u * 6u) & 63u];
        ss << base64_fill;
        ss << base64_fill;
    } else if (remainder == 2u) {
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64_chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64_chars[(combined >> 2u * 6u) & 63u];
        /* Shift the z for 6 spots to the right, e.g. 00000000 00000000 00000000 00yyyyzz */
        ss << base64_chars[(combined >> 1u * 6u) & 63u];
        ss << base64_fill;
    }

    return ss.str();
}

std::string EVEAuth::Base64::encode_url_safe() noexcept
{
    std::string str = encode();
    std::replace(str.begin(), str.end(), base64_url_safe_chars[0], base64_url_safe_chars[1]);
    std::replace(str.begin(), str.end(), base64_url_safe_chars[2], base64_url_safe_chars[3]);

    /* Replace base64_fill with base64_url_safe_fill after encoding */
    for (int i = 0; (i = str.find(base64_fill, i)) != std::string::npos; i += base64_url_safe_fill.length()) {
        str.replace(i, base64_fill.length(), base64_url_safe_fill);
    }

    return str;
}

std::string EVEAuth::Base64::decode() noexcept
{
    return decode(input_str);
}

std::string EVEAuth::Base64::decode(const std::string &str) noexcept(false)
{
    std::size_t str_size = str.size();
    std::size_t fill_size = base64_fill.size();
    char fill_count = 0;

    /* Count the number of fills at the end of the inputString */
    while (str_size > fill_size) {
        if (str.substr(str_size - fill_size, fill_size) == base64_fill) {
            fill_count++;
            str_size -= fill_size;
            if (fill_count > 2) {
                /* Throw an exception if more than 2 fills have been found */
                throw Base64Exception(ERR_TOO_MANY_FILLS, ERR_TOO_MANY_FILLS_CODE);
            }
        } else {
            break;
        }
    }

    /* Check if the number of characters is a dividable by 4, since 4 characters become 3 */
    if (((str_size + fill_count) % 4) != 0) {
        /* Throw an exception if the length is not dividable by 4 */
        throw Base64Exception(ERR_WRONG_LENGTH, ERR_WRONG_LENGTH_CODE);
    }

    /* Calculate the final size of the result string */
    std::size_t out_size = (str_size / 4) * 3;
    std::string result;

    /* Set the size of the result string to the calculated final size */
    result.reserve(out_size);

    std::size_t size_without_fill = str_size - str_size % 4;
    std::array<uint32_t, 4> nums = {0u, 0u, 0u, 0u};
    std::size_t l = 0;

    /* Do for the string without fills */
    while (l < size_without_fill) {

        /* Get the first 4 bytes of the related first 4 character and save them into 32 bit */
        for (std::size_t k = 0; k < nums.size(); k++) {
            nums[k] = find_base_char(str[k + l]);
        }

        /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxyy yyyyzzzz zzqqqqqq */
        uint32_t combined = (nums[0] << 3u * 6u) + (nums[1] << 2u * 6u) + (nums[2] << 6u) + nums[3];

        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 xxxxxxyy */
        result += (combined >> 2u * 8u);
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 yyyyzzzz */
        result += ((combined >> 8u) & 255u);
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 zzqqqqqq */
        result += (combined & 255u);

        l += 4;
    }

    /* Return the string if the there was no fill */
    if (fill_count == 0) {
        return result;
    }

    /* Get first of 4 characters */
    uint32_t first = find_base_char(str[size_without_fill]);
    /* Get second of 4 characters */
    uint32_t second = find_base_char(str[size_without_fill + 1]);

    /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxyy yyyy0000 00000000 */
    uint32_t combined_2 = (first << 3u * 6u) + (second << 2u * 6u);

    if (fill_count == 1) {
        /* Get third of 4 characters and combine, e.g. 00000000 xxxxxxyy yyyyzzzz zz000000 */
        combined_2 = combined_2 + (find_base_char(str[size_without_fill + 2]) << 6u);
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 xxxxxxyy */
        result += ((combined_2 >> 2u * 8u) & 255u);
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 yyyyyyzz */
        result += ((combined_2 >> 8u) & 255u);
    } else if (fill_count == 2) {
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 xxxxxxyy */
        result += ((combined_2 >> 2u * 8u) & 255u);
    }

    return result;
}

std::string EVEAuth::Base64::decode_url_safe() noexcept
{
    std::string str = input_str;
    std::replace(str.begin(), str.end(), base64_url_safe_chars[1], base64_url_safe_chars[0]);
    std::replace(str.begin(), str.end(), base64_url_safe_chars[3], base64_url_safe_chars[2]);

    /* Replace base64_url_safe_fill with base64_fill before decoding */
    for (int i = 0; (i = str.find(base64_url_safe_fill, i)) != std::string::npos; i += base64_fill.length()) {
        str.replace(i, base64_url_safe_fill.length(), base64_fill);
    }

    return decode(str);
}

std::size_t EVEAuth::Base64::find_base_char(const char &c) noexcept(false)
{
    for (std::size_t i = 0; i < base64_chars.size(); i++) {
        if (base64_chars[i] == c) {
            return i;
        }
    }

    throw Base64Exception(ERR_NO_BASE_CHAR_FOUND, ERR_NO_BASE_CHAR_FOUND_CODE);
}

EVEAuth::Base64::~Base64() noexcept = default;
