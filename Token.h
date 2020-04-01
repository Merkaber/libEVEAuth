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
        const std::string& get_base64_header() const noexcept;
        const std::string& get_payload() const noexcept;
        const std::string& get_base64_payload() const noexcept;
        const std::string& get_signature() const noexcept;
        const std::string& get_base64_signature() const noexcept;
        const std::string& get_access_token() const noexcept;
        const std::string& get_character_id() const noexcept;
        const std::string& get_character_name() const noexcept;

        void set_access_token(const std::string& m_access_token) noexcept;

        const std::string& get_token_type() const noexcept;
        void set_token_type(const std::string& m_token_type) noexcept;

        const std::string& get_refresh_token() const noexcept;
        void set_refresh_token(const std::string& m_refresh_token) noexcept;

        const int& get_expires_in() const noexcept;
        void set_expires_in(const int& m_expires_in) noexcept;

    public:
        /* By default, we use RS256 as signature algorithm */
        static const std::string algorithm;

    private:
        std::string header = "";
        std::string base64_header = "";
        std::string payload = "";
        std::string base64_payload = "";
        std::string signature = "";
        std::string base64_signature = "";

        std::string access_token = "";
        std::string token_type = "";
        std::string refresh_token = "";
        int expires_in = 0;

        std::string character_id = "";
        std::string character_name = "";
    };
}
