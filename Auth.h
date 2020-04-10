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

/*
 * Buffer size for the generate_pem_key function
 * This size is used to convert the BIO* into std::string
 * The actual size of the data might be less
 */
#define PEM_BUFF_SIZE 4096

/* Base64 Exception Range from 100 - 199 */
#define F_GCC_NAME "generate_code_challenge(): "
#define F_GH_NAME "generate_hash(): "
#define F_GAU_NAME "generate_auth_url(): "
#define F_CR_NAME "curl_request(): "

#define F_STR_NAME "send_token_request(): "
#define ERR_STR_CODE 104

#define F_SJWTR_NAME "send_jwt_request(): "
#define ERR_SJWTR_CODE 108

#define F_SRR_NAME "send_refresh_request(): "
#define ERR_SRR_CODE 112

#define F_PTR_NAME "parse_token_request(): "

#define ERR_CR_REQ "curl_easy_perform(): failed! "
#define ERR_CR_REQ_CODE 114
#define ERR_CR_RSP "curl response was not 200! "
#define ERR_CR_RSP_CODE 115

#define ERR_HASH_CTX "Could not create hash context! "
#define ERR_HASH_CTX_CODE 100
#define ERR_HASH_INIT "Could not initialize hash! "
#define ERR_HASH_INIT_CODE 101
#define ERR_HASH_UPDATE "Could not update hash! "
#define ERR_HASH_UPDATE_CODE 102
#define ERR_HASH_FINAL "Final hash failed! "
#define ERR_HASH_FINAL_CODE 103

#define ERR_PARSE_PICOJSON "picojson: "
#define ERR_PARSE_PICOJSON_CODE 106

#define ERR_VFT_PICOJSON_PARSE "verify_token(): picojson: parse error!"
#define ERR_VFT_PICOJSON_PARSE_CODE 110

#define ERR_VFT_VRF "verify_token(): token verification failed!"
#define ERR_VFT_VRF_CODE 111

namespace EVEAuth {

    /**
     * Exception class for authentication
     *
     * The exception thrown will always have an unique exception code
     */
    class AuthException : public std::exception {
    public:

        /**
         * This constructor expects the error message and the related error code
         * @param message The message which will be available when calling what()
         * @param error_code The unique error code which will be available when calling get_error_code()
         */
        AuthException(std::string message, int error_code) noexcept;

        /**
         * Returns the error message as c-string which has been set when the exception was thrown
         * @return The error message which specifies what kind of exception has been thrown
         */
        const char* what() const noexcept override;

        /**
         * Returns the error code which has been set when the exception was thrown
         * @return The unique error code which specifies what kind of exception has been thrown
         */
        const int& get_error_code() const noexcept;

    private:
        /// The error message which will be set when the AuthException is thrown
        const std::string message;

        /// The unique error code which will be set when the AuthException is thrown
        const int error_code;
    };

    class Auth {
    public:
        Auth(std::string& client_id, std::string& scope_val) noexcept;
        ~Auth() noexcept;

        const std::string& get_client_id() const noexcept;
        const std::string& get_scope_val() const noexcept;

        const std::string& get_authentication_url() const noexcept;
        void set_authentication_url(const std::string& m_authentication_url) noexcept;

        const std::string& get_code_val() const noexcept;
        void set_code_val(const std::string& m_code_val) noexcept;

        /**
         * Generates the authentication url for the web-login
         * @return The authentication url which will lead to a web-login
         */
        const std::string& generate_auth_url() noexcept(false);

        /**
         * Starts the token request and validation
         * @return If successful, returns the token for authentication
         */
        EVEAuth::Token* start() noexcept(false);

    private:

        /**
         * Generates the code challenge and code verifier
         */
        void generate_code_challenge() noexcept(false);

        /**
         * Generates the authentication url if none is given
         */
        void put_url_together() noexcept;

        /**
         * Sends the token request
         */
        void send_token_request() noexcept(false);

        /**
         * Verifies the current token
         */
        void verify_token() noexcept(false);

        /**
         * Parse the last download_response and set the data to the token object
         */
        void parse_token_request() noexcept(false);

        /**
         * Sends the jwt request
         */
        void send_jwt_request() noexcept(false);

        /**
         * Refresh the current token
         */
        void refresh_token() noexcept(false);

        /**
         * Sends the refresh token request
         */
        void send_refresh_request() noexcept(false);

        /**
         * Makes a curl request with the given post fields appended to the request_url
         * @param url The url to which the request will be made
         * @param post_fields The post fields for the request
         */
        void curl_request(const std::string& url, const std::string& post_fields) noexcept(false);

    private:

        /// The client_id which is necessary for identifying the application
        const std::string client_id;

        /// The code challenge which is necessary for requesting the token
        std::string code_challenge = "";

        /// The verifier which is necessary for requesting the token
        std::string code_verifier = "";

        /// The whole authentication for requesting the user login
        std::string authentication_url = "";

        /// The code value which needs to be set after user login
        std::string code_val = "";

        /// The scope defines which data can be accessed through authentication
        const std::string scope_val;

        /// The last download response
        std::string download_response = "";

        /// The token which will hold the information for authentication
        EVEAuth::Token* token = nullptr;

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

        const std::string& get_grant_type_refresh_val() const noexcept;
        void set_grant_type_refresh_val(const std::string& m_grant_type_refresh_val) noexcept;

        const std::string& get_refresh_token_param() const noexcept;
        void set_refresh_token_param(const std::string& m_refresh_token_param) noexcept;

        const std::string& get_cacert_path() const noexcept;
        void set_cacert_path(const std::string& m_cacert_path) noexcept;

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
        std::string grant_type_refresh_val = "refresh_token";
        std::string refresh_token_param = "refresh_token=";

        std::string cacert_path = "C:\\Users\\Merkaber\\Documents\\dev\\libEVEAuth\\cacert.pem";
    };

    /**
     * Simple struct for curl write function write_memory_callback
     */
    struct MemoryStruct {
        char* memory;
        size_t size;
    };

    /**
     * Curl write function
     */
    static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp);

    /**
     * Generates the hash value of the given std::string s
     * @param s The given string
     * @return The hash value if successfully hashed, otherwise an empty std::string
     */
    std::string generate_hash(const std::string& s) noexcept(false);

    /**
     * Generates a public RSA key in pem format and returns it as std::string
     * @param n The base64 encoded modulus
     * @param e The base64 encoded exponent
     * @return The public RSA key in pem format as std::string if successful
     */
    std::string generate_pem_key(const std::string& n, const std::string& e) noexcept;
}