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
        Token() noexcept(false);

        void decode_access_token() noexcept;

    /* Getter and setter for private fields */
    public:
        const std::string& get_header() const noexcept;
        const std::string& get_payload() const noexcept;
        const std::string& get_signature() const noexcept;
        const std::string& get_algorithm() const noexcept;

        const std::string& get_access_token() const noexcept;
        void set_access_token(const std::string& m_access_token) noexcept;

        const std::string& get_token_type() const noexcept;
        void set_token_type(const std::string& m_token_type) noexcept;

        const std::string& get_refresh_token() const noexcept;
        void set_refresh_token(const std::string& m_refresh_token) noexcept;

        const int& get_expires_in() const noexcept;
        void set_expires_in(const int& m_expires_in) noexcept;

    private:
        std::string header = "";
        std::string payload = "";
        std::string signature = "";

        std::string access_token = "";
        std::string token_type = "";
        std::string refresh_token = "";
        int expires_in = 0;

        /* By default, we use RS256 as signature algorithm */
        const std::string algorithm = "RS256";
    };
}
