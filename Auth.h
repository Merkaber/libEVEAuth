/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"

/*
 * The number of bytes which is necessary for the PKCE protocol
 * Specification: https://tools.ietf.org/html/rfc7636
 */
#define PKCE_BYTE_NUM 32

namespace EVEAuth {
    class Auth {
    public:
        explicit Auth(std::string& client_id) noexcept;

        void connect() noexcept;

    private:

        void generate_code_challenge() noexcept;

    private:
        const std::string client_id;

        std::string code_challenge = "";

        std::string code_verifier = "";
    };

    /**
     * Generates the hash value of the given std::string s
     * @param s The given string
     * @return The hash value if successfully hashed, otherwise an empty std::string
     */
    std::string generate_hash(const std::string& s) noexcept;
}