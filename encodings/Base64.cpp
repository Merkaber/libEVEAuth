/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Base64.h"

EVEAuth::Base64::Base64(std::string inputStr) noexcept : inputStr(std::move(inputStr))
{

}

std::string EVEAuth::Base64::encode() noexcept
{
    std::size_t inputSize = inputStr.size();
    uint8_t remainder = inputSize % 3u;
    size_t diff_size = inputSize - remainder;
    std::stringstream ss;

    for (std::size_t i = 0; i < diff_size;) {
        uint32_t b_1 = inputStr[i];
        uint32_t b_2 = inputStr[i + 1];
        uint32_t b_3 = inputStr[i + 2];

        uint32_t combined = (b_1 << 16u) + (b_2 << 8u) + b_3;

        ss << base64Chars[(combined >> 3u * 6u) & 63u];
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
        ss << base64Chars[(combined >> 1u * 6u) & 63u];
        ss << base64Chars[(combined) & 63u];

        i += 3;
    }

    if (remainder == 0u) {
        return ss.str();
    }

    std::vector<uint32_t> paddingArray;
    for (uint8_t i = 0u; i < 3u; ++i) {
        if (diff_size < inputSize) {
            paddingArray.push_back(inputStr[diff_size]);
            diff_size++;
        } else {
            paddingArray.push_back(0u);
        }
    }

    uint32_t combined = (paddingArray.at(0) << 16u) + (paddingArray.at(1) << 8u) + paddingArray.at(2);

    if (remainder == 1u) {
        ss << base64Chars[(combined >> 3u * 6u) & 63u];
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
        ss << base64Fill;
        ss << base64Fill;
    } else if (remainder == 2u) {
        ss << base64Chars[(combined >> 3u * 6u) & 63u];
        ss << base64Chars[(combined >> 2u * 6u) & 63u];
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

    for (int i = 0; (i = str.find(base64Fill, i)) != std::string::npos; i += base64UrlSafeFill.length()) {
        str.replace(i, base64Fill.length(), base64UrlSafeFill);
    }

    return str;
}

std::string EVEAuth::Base64::decode() noexcept
{
    return decode(inputStr);
}

std::string EVEAuth::Base64::decode(const std::string &str) noexcept
{
    std::size_t strSize = str.size();
    std::size_t fillSize = base64Fill.size();
    char fillCount = 0;

    while (strSize > fillSize) {
        if (str.substr(strSize - fillSize, fillSize) == base64Fill) {
            fillCount++;
            strSize -= fillSize;
            if (fillCount > 2) {
                return "";
            }
        } else {
            break;
        }
    }

    if (((strSize + fillCount) % 4) != 0) {
        return "";
    }

    std::size_t outSize = (strSize / 4) * 3;
    std::string result;
    result.reserve(outSize);

    std::size_t sizeWithoutFill = strSize - strSize % 4;
    std::array<uint32_t, 4> nums = {0u, 0u, 0u, 0u};
    std::size_t l = 0;
    while (l < sizeWithoutFill) {
        for (std::size_t k = 0; k < nums.size(); k++) {
            for (std::size_t j = 0; j < base64Chars.size(); j++) {
                if (base64Chars[j] == str[k + l]) {
                    nums[k] = j;
                }
            }
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

    uint32_t fill_1 = 0;
    for (std::size_t i = 0; i < base64Chars.size(); i++) {
        if (base64Chars[i] == str[sizeWithoutFill]) {
            fill_1 = i;
        }
    }

    uint32_t fill_2 = 0;
    for (std::size_t i = 0; i < base64Chars.size(); i++) {
        if (base64Chars[i] == str[sizeWithoutFill + 1]) {
            fill_2 = i;
        }
    }

    uint32_t check = 0;
    for (std::size_t i = 0; i < base64Chars.size(); i++) {
        if (base64Chars[i] == str[sizeWithoutFill + 2]) {
            check = i;
        }
    }

    uint32_t combined_2 = (fill_1 << 3u * 6u) + (fill_2 << 2u * 6u);

    if (fillCount == 1) {
        combined_2 |= check << 6u;
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

    for (int i = 0; (i = str.find(base64UrlSafeFill, i)) != std::string::npos; i += base64Fill.length()) {
        str.replace(i, base64UrlSafeFill.length(), base64Fill);
    }

    return decode(str);
}

std::size_t EVEAuth::Base64::findBaseChar(const char &c)
{
    for (std::size_t i = 0; i < base64Chars.size(); i++) {
        if (base64Chars[i] == c) {
            return i;
        }
    }
}

EVEAuth::Base64::~Base64() noexcept = default;
