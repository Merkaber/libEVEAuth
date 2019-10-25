/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Base64.h"

EVEAuth::Base64::Base64(std::string inputStr) noexcept : inputStr(std::move(inputStr))
{

}

std::string EVEAuth::Base64::encode()
{
    std::size_t inputSize = inputStr.size();
    u_int8_t rest = inputSize % 3;
    if (rest == 0) {

    }
}

std::string EVEAuth::Base64::decode()
{

}

EVEAuth::Base64::~Base64() noexcept = default;
