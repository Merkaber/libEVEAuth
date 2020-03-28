/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"
#include "Token.h"

/*
 * The number of bytes which is necessary for the PKCE protocol
 * Specification: https://tools.ietf.org/html/rfc7636
 */
#define PKCE_BYTE_NUM 32

namespace EVEAuth {
    class Auth {
    public:
        explicit Auth(std::string& client_id) noexcept;
        ~Auth() noexcept;

        const std::string& get_scope_val() const noexcept;
        void set_scope_val(const std::string& m_scope_val) noexcept;

        const std::string& get_authentication_url() const noexcept;
        void set_authentication_url(const std::string& m_authentication_url) noexcept;

        const std::string& get_code_val() const noexcept;
        void set_code_val(const std::string& m_code_val) noexcept;

        /**
         * Generates the authentication url for the web-login
         * @return The authentication url
         */
        std::string& generate_auth_url() noexcept;

        /**
         *
         * @return
         */
        const EVEAuth::Token& get_token() noexcept;

    private:

        /**
         * Generates the code challenge and code verifier
         */
        void generate_code_challenge() noexcept;

        /**
         * Generates the authentication url if none is given
         */
        void put_url_together() noexcept;

        /**
         * Sends the token request
         */
        void send_token_request() noexcept;

        void verify_token() noexcept;

        /**
         * Parse the last download_response and set the data to the token object
         */
        void parse_token_request() noexcept;

    private:
        const std::string client_id;

        std::string code_challenge = "";

        std::string code_verifier = "";

        std::string authentication_url = "";

        std::string code_val = "";

        /* The scope defines which data can be accessed through authentication */
        std::string scope_val = "";

        /* The current curl response */
        bool curl_response = false;

        /* The current download response */
        std::string download_response = "";

        std::string token_response = "";

        EVEAuth::Token* token;

        /* Getter and setter for predefined query parameters and values */
    public:
        const std::string& get_host() const noexcept;
        void set_host(const std::string& m_host) noexcept;

        const std::string& get_content_type() const noexcept;
        void set_content_type(const std::string& m_content_type) noexcept;

        const std::string& get_base_url() const noexcept;
        void set_base_url(const std::string& m_base_url) noexcept;

        const std::string& get_request_url() const noexcept;
        void set_request_url(const std::string& m_request_url) noexcept;

        const std::string& get_jwt_keys_url() const noexcept;
        void set_jwt_keys_url(const std::string& m_jwt_keys_url) noexcept;

        const std::string& get_curl_agent() const noexcept;
        void set_curl_agent(const std::string& m_curl_agent) noexcept;

        const std::string& get_response_type_param() const noexcept;
        void set_response_type_param(const std::string& m_response_type_param) noexcept;

        const std::string& get_redirect_url_param() const noexcept;
        void set_redirect_url_param(const std::string& m_redirect_url_param) noexcept;

        const std::string& get_client_id_param() const noexcept;
        void set_client_id_param(const std::string& m_client_id_param) noexcept;

        const std::string& get_scope_param() const noexcept;
        void set_scope_param(const std::string& m_scope_param) noexcept;

        const std::string& get_state_param() const noexcept;
        void set_state_param(const std::string& m_state_param) noexcept;

        const std::string& get_code_challenge_param() const noexcept;
        void set_code_challenge_param(const std::string& m_code_challenge_param) noexcept;

        const std::string& get_code_challenge_method_param() const noexcept;
        void set_code_challenge_method_param(const std::string& m_code_challenge_method_param) noexcept;

        const std::string& get_grant_type_param() const noexcept;
        void set_grant_type_param(const std::string& m_grant_type_param) noexcept;

        const std::string& get_code_param() const noexcept;
        void set_code_param(const std::string& m_code_param) noexcept;

        const std::string& get_code_verifier_param() const noexcept;
        void set_code_verifier_param(const std::string& m_code_verifier_param) noexcept;

        const std::string& get_state_val() const noexcept;
        void set_state_val(const std::string& m_state_val) noexcept;

        const std::string& get_code_challenge_method_val() const noexcept;
        void set_code_challenge_method_val(const std::string& m_code_challenge_method_val) noexcept;

        const std::string& get_redirect_url_val() const noexcept;
        void set_redirect_url_val(const std::string& m_redirect_url_val) noexcept;

        const std::string& get_response_type_val() const noexcept;
        void set_response_type_val(const std::string& m_response_type_val) noexcept;

        const std::string& get_grant_type_val() const noexcept;
        void set_grant_type_val(const std::string& m_grant_type_val) noexcept;

        /* Predefined query parameter and values for login */
    private:
        std::string host = "login.eveonline.com";
        std::string content_type = "application/x-www-form-urlencoded";
        std::string base_url = "https://login.eveonline.com/v2/oauth/authorize/";
        std::string request_url = "https://login.eveonline.com/v2/oauth/token";
        std::string jwt_keys_url = "https://login.eveonline.com/oauth/jwks";
        std::string curl_agent = "libcurl-agent/1.0";

        std::string response_type_param = "response_type=";
        std::string redirect_url_param = "redirect_uri=";
        std::string client_id_param = "client_id=";
        std::string scope_param = "scope=";
        std::string state_param = "state=";
        std::string code_challenge_param = "code_challenge=";
        std::string code_challenge_method_param = "code_challenge_method=";
        std::string grant_type_param = "grant_type=";
        std::string code_param = "code=";
        std::string code_verifier_param = "code_verifier=";

        std::string state_val = "unique-state";
        std::string code_challenge_method_val = "S256";
        std::string redirect_url_val = "https%3A%2F%2Flocalhost%2Fcallback%2F";
        std::string response_type_val = "code";
        std::string grant_type_val = "authorization_code";

    };

    struct MemoryStruct {
        char* memory;
        size_t size;
    };

    static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp);

    /**
     * Generates the hash value of the given std::string s
     * @param s The given string
     * @return The hash value if successfully hashed, otherwise an empty std::string
     */
    std::string generate_hash(const std::string& s) noexcept;
}