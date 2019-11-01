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
    std::stringstream ss;

    for (std::size_t i = 0; i < inputSize;) {
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

    size_t diff_size = inputSize - remainder;

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
    
}

std::string EVEAuth::Base64::decode() noexcept
{
    return "";
}

std::string EVEAuth::Base64::decodeUrlSafe() noexcept
{
    return "";
}

EVEAuth::Base64::~Base64() noexcept = default;
