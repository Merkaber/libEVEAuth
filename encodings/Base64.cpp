/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Base64.h"
#include <algorithm>

EVEAuth::Base64Exception::Base64Exception(std::string message, const int errorCode) : message(std::move(message)), errorCode(errorCode)
{

}

const char* EVEAuth::Base64Exception::what() const noexcept
{
    return message.c_str();
}

int EVEAuth::Base64Exception::getErrorCode() const noexcept
{
    return errorCode;
}

EVEAuth::Base64::Base64(std::string inputStr) noexcept : inputStr(std::move(inputStr))
{

}

std::string EVEAuth::Base64::encode() noexcept
{
    std::size_t inputSize = inputStr.size();

    /* InputSize mod 3, since 3 characters (byte) becoming 4 characters */
    uint8_t remainder = inputSize % 3u;

    /* Get the inputSize without remainder */
    size_t diff_size = inputSize - remainder;
    std::stringstream ss;

    /* Do for the first 3*n characters */
    for (std::size_t i = 0; i < diff_size;) {

        /* Get the 3 bytes and save each of them into 32 bit */
        uint32_t b_1 = inputStr[i];
        uint32_t b_2 = inputStr[i + 1];
        uint32_t b_3 = inputStr[i + 2];

        /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxxx yyyyyyyy zzzzzzzz */
        uint32_t combined = (b_1 << 16u) + (b_2 << 8u) + b_3;

        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64Chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
        /* Shift the z for 6 spots to the right, e.g. 00000000 00000000 00000000 00yyyyzz*/
        ss << base64Chars[(combined >> 6u) & 63u];
        /* Get the last z's, e.g. 00000000 00000000 00000000 00zzzzzz */
        ss << base64Chars[(combined) & 63u];

        i += 3;
    }

    /* Return the string if there was no remainder */
    if (remainder == 0u) {
        return ss.str();
    }

    std::vector<uint32_t> paddingArray;
    /* Save the remaining characters into paddingArray */
    for (uint8_t i = 0u; i < 2u; ++i) {
        if (diff_size < inputSize) {
            paddingArray.push_back(inputStr[diff_size]);
            diff_size++;
        } else {
            /* Save 0 if there was only one remaining character */
            paddingArray.push_back(0u);
        }
    }

    /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxxx yyyyyyyy 00000000 */
    uint32_t combined = (paddingArray.at(0) << 16u) + (paddingArray.at(1) << 8u);

    if (remainder == 1u) {
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64Chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
        ss << base64Fill;
        ss << base64Fill;
    } else if (remainder == 2u) {
        /* Shift the x for 18 spots to the right, e.g. 00000000 00000000 00000000 00xxxxxx */
        ss << base64Chars[combined >> 3u * 6u];
        /* Shift the y for 12 spots to the right, e.g. 00000000 00000000 00000000 00xxyyyy */
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
        /* Shift the z for 6 spots to the right, e.g. 00000000 00000000 00000000 00yyyyzz */
        ss << base64Chars[(combined >> 1u * 6u) & 63u];
        ss << base64Fill;
    }

    return ss.str();
}

std::string EVEAuth::Base64::encodeUrlSafe() noexcept
{
    std::string str = encode();
    std::replace(str.begin(), str.end(), base64UrlSafeChars[0], base64UrlSafeChars[1]);
    std::replace(str.begin(), str.end(), base64UrlSafeChars[2], base64UrlSafeChars[3]);

    /* Replace base64Fill with base64UrlSafeFill after encoding */
    for (int i = 0; (i = str.find(base64Fill, i)) != std::string::npos; i += base64UrlSafeFill.length()) {
        str.replace(i, base64Fill.length(), base64UrlSafeFill);
    }

    return str;
}

std::string EVEAuth::Base64::decode() noexcept
{
    return decode(inputStr);
}

std::string EVEAuth::Base64::decode(const std::string &str) noexcept(false)
{
    std::size_t strSize = str.size();
    std::size_t fillSize = base64Fill.size();
    char fillCount = 0;

    while (strSize > fillSize) {
        if (str.substr(strSize - fillSize, fillSize) == base64Fill) {
            fillCount++;
            strSize -= fillSize;
            if (fillCount > 2) {

                throw Base64Exception(ERR_TOO_MANY_FILLS, ERR_TOO_MANY_FILLS_CODE);
            }
        } else {
            break;
        }
    }

    if (((strSize + fillCount) % 4) != 0) {

        throw Base64Exception(ERR_WRONG_LENGTH, ERR_WRONG_LENGTH_CODE);
    }

    std::size_t outSize = (strSize / 4) * 3;
    std::string result;
    result.reserve(outSize);

    std::size_t sizeWithoutFill = strSize - strSize % 4;
    std::array<uint32_t, 4> nums = {0u, 0u, 0u, 0u};
    std::size_t l = 0;
    while (l < sizeWithoutFill) {
        for (std::size_t k = 0; k < nums.size(); k++) {
            nums[k] = findBaseChar(str[k+l]);
        }

        uint32_t combined = (nums[0] << 3u * 6u) + (nums[1] << 2u * 6u) + (nums[2] << 6u) + nums[3];

        result += ((combined >> 2u * 8u) & 255u);
        result += ((combined >> 8u) & 255u);
        result += (combined & 255u);

        l += 4;
    }

    if (fillCount == 0) {
        return result;
    }

    uint32_t fill_1 = findBaseChar(str[sizeWithoutFill]);
    uint32_t fill_2 = findBaseChar(str[sizeWithoutFill + 1]);

    uint32_t combined_2 = (fill_1 << 3u * 6u) + (fill_2 << 2u * 6u);

    if (fillCount == 1) {
        combined_2 |= findBaseChar(str[sizeWithoutFill + 2]) << 6u;
        result += ((combined_2 >> 2u * 8u) & 255u);
        result += ((combined_2 >> 8u) & 255u);
    } else if (fillCount == 2) {
        result += ((combined_2 >> 2u * 8u) & 255u);
    }

    return result;
}

std::string EVEAuth::Base64::decodeUrlSafe() noexcept
{
    std::string str = inputStr;
    std::replace(str.begin(), str.end(), base64UrlSafeChars[1], base64UrlSafeChars[0]);
    std::replace(str.begin(), str.end(), base64UrlSafeChars[3], base64UrlSafeChars[2]);

    /* Replace base64UrlSafeFill with base64Fill before decoding */
    for (int i = 0; (i = str.find(base64UrlSafeFill, i)) != std::string::npos; i += base64Fill.length()) {
        str.replace(i, base64UrlSafeFill.length(), base64Fill);
    }

    return decode(str);
}

std::size_t EVEAuth::Base64::findBaseChar(const char &c) noexcept(false)
{
    for (std::size_t i = 0; i < base64Chars.size(); i++) {
        if (base64Chars[i] == c) {
            return i;
        }
    }

    throw Base64Exception(ERR_NO_BASE_CHAR_FOUND, ERR_NO_BASE_CHAR_FOUND_CODE);
}

EVEAuth::Base64::~Base64() noexcept = default;
