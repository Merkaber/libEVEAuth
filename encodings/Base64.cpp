/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Base64.h"
#include <algorithm>

constexpr std::array<char, 64> EVEAuth::Base64::base64Chars;
constexpr std::array<char, 4> EVEAuth::Base64::base64UrlSafeChars;

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

    /* Count the number of fills at the end of the inputString */
    while (strSize > fillSize) {
        if (str.substr(strSize - fillSize, fillSize) == base64Fill) {
            fillCount++;
            strSize -= fillSize;
            if (fillCount > 2) {
                /* Throw an Exception if more than 2 fills have been found */
                throw Base64Exception(ERR_TOO_MANY_FILLS, ERR_TOO_MANY_FILLS_CODE);
            }
        } else {
            break;
        }
    }

    /* Check if the number of characters is a dividable by 4, since 4 characters become 3 */
    if (((strSize + fillCount) % 4) != 0) {
        /* Throw an Exception if the length is not dividable by 4 */
        throw Base64Exception(ERR_WRONG_LENGTH, ERR_WRONG_LENGTH_CODE);
    }

    /* Calculate the final size of the result string */
    std::size_t outSize = (strSize / 4) * 3;
    std::string result;

    /* Set the size of the result string to the calculated final size */
    result.reserve(outSize);

    std::size_t sizeWithoutFill = strSize - strSize % 4;
    std::array<uint32_t, 4> nums = {0u, 0u, 0u, 0u};
    std::size_t l = 0;

    /* Do for the string without fills */
    while (l < sizeWithoutFill) {

        /* Get the first 4 bytes of the related first 4 character and save them into 32 bit */
        for (std::size_t k = 0; k < nums.size(); k++) {
            nums[k] = findBaseChar(str[k + l]);
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
    if (fillCount == 0) {
        return result;
    }

    /* Get first of 4 characters */
    uint32_t first = findBaseChar(str[sizeWithoutFill]);
    /* Get second of 4 characters */
    uint32_t second = findBaseChar(str[sizeWithoutFill + 1]);

    /* Combine them, starting from the 24th bit, e.g. 00000000 xxxxxxyy yyyy0000 00000000 */
    uint32_t combined_2 = (first << 3u * 6u) + (second << 2u * 6u);

    if (fillCount == 1) {
        /* Get third of 4 characters and combine, e.g. 00000000 xxxxxxyy yyyyzzzz zz000000 */
        combined_2 = combined_2 + (findBaseChar(str[sizeWithoutFill + 2]) << 6u);
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 xxxxxxyy */
        result += ((combined_2 >> 2u * 8u) & 255u);
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 yyyyyyzz */
        result += ((combined_2 >> 8u) & 255u);
    } else if (fillCount == 2) {
        /* Shift the x for 16 spots to the right, e.g. 00000000 00000000 00000000 xxxxxxyy */
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
