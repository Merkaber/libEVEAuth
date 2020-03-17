/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"

namespace EVEAuth {
    class Auth {
    public:
        Auth(std::string& client_id);

    private:
        const std::string client_id;
    };

    /**
     * Generates the hash value of the given std::string s
     * @param s The given string
     * @return The hash value if successfully hashed, otherwise an empty std::string
     */
    std::string generate_hash(const std::string& s) noexcept;
}