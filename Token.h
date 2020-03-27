/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"

namespace EVEAuth {
    class Token {
    public:
        explicit Token(std::string& access_token) noexcept;

    private:
        const std::string access_token = "";

    };
}
