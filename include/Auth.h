/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include <vector>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

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
#define ERR_STR_CODE 106

#define F_SJWTR_NAME "send_jwt_request(): "
#define ERR_SJWTR_CODE 107

#define F_SRR_NAME "send_refresh_request(): "
#define ERR_SRR_CODE 111

#define F_PTR_NAME "parse_token_request(): "
#define F_VFT_NAME "verify_token(): "

#define F_SA_NAME "start(): "
#define ERR_SA_NO_CV "No code value was set! Set code value and call start() again! "
#define ERR_SA_NO_CV_CODE 112

#define F_RT_NAME "refresh_token(): "
#define F_SRT_NAME "start_refresh_token(): "

#define F_Q_NAME "auth_query(): "
#define ERR_QC_REQ "curl_easy_perform(): failed! "
#define ERR_QC_REQ_CODE 113
#define ERR_QC_RSP "curl response was not 200! "
#define ERR_QC_RSP_CODE 114

#define ERR_CR_REQ "curl_easy_perform(): failed! "
#define ERR_CR_REQ_CODE 104
#define ERR_CR_RSP "curl response was not 200! "
#define ERR_CR_RSP_CODE 105

#define ERR_HASH_CTX "Could not create hash context! "
#define ERR_HASH_CTX_CODE 100
#define ERR_HASH_INIT "Could not initialize hash! "
#define ERR_HASH_INIT_CODE 101
#define ERR_HASH_UPDATE "Could not update hash! "
#define ERR_HASH_UPDATE_CODE 102
#define ERR_HASH_FINAL "Final hash failed! "
#define ERR_HASH_FINAL_CODE 103

#define ERR_PARSE_PICOJSON "picojson: "
#define ERR_PARSE_PICOJSON_CODE 108

#define ERR_VFT_ALG "The header algorithm does not match the token algorithm! "
#define ERR_VFT_ALG_CODE 109

#define ERR_VFT_VRF "Token verification failed! "
#define ERR_VFT_VRF_CODE 110

namespace EVEAuth {

    class CallBackTimer;
    class Token;

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

    /**
     * The authorization class which handles everything
     *
     * Create an object of this class with the client_id of the application and the scope you will auth_query to
     */
    class Auth {
    public:

        /**
         * Create an authorization object with the applications client_id and the scope you will auth_query to
         * @param client_id The applications client_id which you will find on the developer webpage
         * @param scope_val The scope of the application
         */
        Auth(std::string& client_id, std::string& scope_val) noexcept;

        /**
         * When the object is destroyed, the token will be destroyed and everything related to curl will be cleaned up
         */
        ~Auth() noexcept;

        /**
         * Get the current client_id which will be used for authorization
         * @return The current client_id
         */
        const std::string& get_client_id() const noexcept;

        /**
         * Get the currently set scope which is necessary for authorization
         * @return The current scope
         */
        const std::string& get_scope_val() const noexcept;

        /**
         * Get the currently set or generated authentication url which needs to be called for retrieving the code value
         *
         * The code value then have to be set to this EVEAuth object
         * @return The currently set or generated authentication url
         */
        const std::string& get_authentication_url() const noexcept;

        /**
         * Set an authentication url for retrieving the code value
         *
         * Usually you will use the methods of this EVEAuth object to generate the authentication url
         * If you manually generate the authentication url, you can set thise url with this method
         * @param m_authentication_url
         */
        void set_authentication_url(const std::string& m_authentication_url) noexcept;

        /**
         * Get the code value which has to be retrieved from the login of the authentication url
         * @return The currently set code value
         */
        const std::string& get_code_val() const noexcept;

        /**
         * Set the code value which has to be retrieved from the login of the authentication url
         * @param m_code_val The code value from the login
         */
        void set_code_val(const std::string& m_code_val) noexcept;

        /**
         * Get the character id from the login with the generated authentication url with this EVEAuth object
         * @return The character id of the login
         */
        const std::string& get_character_id() const noexcept;

        /**
         * Get the character name from the login with the generated authentication url with this EVEAuth object
         * @return The character name of the login
         */
        const std::string& get_character_name() const noexcept;

        /**
         * Generates the authentication url for the web-login
         * @return The authentication url which will lead to a web-login
         */
        const std::string& generate_auth_url() noexcept(false);

        /**
         * Starts the whole authentication process by its own
         * If an exception is thrown you may create a new Auth object and
         * generate another url to start the authentication process again
         */
        void start() noexcept(false);

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
         * Sends the refresh token request
         */
        void send_refresh_request() noexcept(false);

        /**
         * Starts the refreshing callback thread
         */
        void start_refresh_token() noexcept(false);

        /**
         * Stops the refreshing callback thread
         */
        void stop_refresh_token() noexcept;

        /**
         * Queries from the eve swagger interface with the set query url
         *
         * @param query_val The esi related query string without query_url i.e. https://esi.evetech.net/latest/query_val
         * @param with_authorization Specifies if an access token is need or not, default is false
         * @param post_fields Specifies post fields for the query, default is an empty vector
         * @return A response string in JSON format if no exception was thrown
         */
        std::string auth_query(const std::string& query_val, bool with_authorization = false, const std::vector<std::pair<std::string, std::string>>& post_fields = {}) const noexcept(false);

        /**
         * Queries form the eve swagger interface without authorization
         *
         * @param query_url The full query url
         * @param cacert_path The path to the cacert if platform is windows, otherwise set empty string
         * @param post_fields Specifies post fields for the query, default is an empty vector
         * @return A response string in JSON format if no exception was thrown
         */
        static std::string simple_query(const std::string& query_url, const std::string& cacert_path, const std::vector<std::pair<std::string, std::string>>& post_fields = {}) noexcept(false);

        /**
         * Get the access token which can be used to make a query with authorization
         * @return The current access token
         */
        const std::string& get_access_token() const noexcept;

        /**
         * Get the refresh token which can be used to request a new access token
         * @return The current refresh token
         */
        const std::string& get_refresh_token() const noexcept;
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
         * Sends the jwt request
         */
        void send_jwt_request() noexcept(false);

        /**
         * Refresh the current token
         */
        void refresh_token() noexcept(false);

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

        /// The whole authentication url for requesting the user login
        std::string authentication_url = "";

        /// The code value which needs to be set after user login
        std::string code_val = "";

        /// The scope defines which data can be accessed through authentication
        const std::string scope_val;

        /// The last download response
        std::string download_response = "";

        /// The token which will hold the information for authorization
        EVEAuth::Token* token = nullptr;

        /// The callback timer for refreshing the token
        EVEAuth::CallBackTimer* cba = nullptr;

        /* Getter and setter for predefined auth_query parameters and values */
    public:

        /**
         * Get the current host name which is set to the header of a http request
         * @return The currently set host
         */
        const std::string& get_host() const noexcept;

        /**
         * Set the host which is set to the header of a http request
         *
         * Only set this host if this library is not updated or the host has changed
         * default: login.eveonline.com
         * @param m_host The host which will be set to all http requests
         */
        void set_host(const std::string& m_host) noexcept;

        /**
         * Get the current content type which is set to the header of a http request
         * @return The currently set host
         */
        const std::string& get_content_type() const noexcept;

        /**
         * Set the content type which is set to the header of a http request
         *
         * Only set this content type is this library is not updated or the content type has changed
         * default: application/x-www-form-urlencoded
         * @param m_content_type The content type which will be set to all http requests
         */
        void set_content_type(const std::string& m_content_type) noexcept;

        /**
         * Get the current base url to which all http requests will be made
         * @return The current base url
         */
        const std::string& get_base_url() const noexcept;

        /**
         * Set the base url to which all http requests will be made
         *
         * Only set this base url if this library is not updated or the base url has changed
         * default: https://login.eveonline.com/v2/oauth/authorize/
         * @param m_base_url
         */
        void set_base_url(const std::string& m_base_url) noexcept;

        /**
         * Get the current request url to which all authorization requests will be made
         * @return The current request url
         */
        const std::string& get_request_url() const noexcept;

        /**
         * Set the request url to wich all authorization requests will be made
         *
         * Only set this request url if this library is not updated or the request url has changed
         * default: https://login.eveonline.com/v2/oauth/token
         * @param m_request_url
         */
        void set_request_url(const std::string& m_request_url) noexcept;

        /**
         * Get the current jwt keys url to which the request for the current jwt token will be made
         * @return The current jwt keys url
         */
        const std::string& get_jwt_keys_url() const noexcept;

        /**
         * Set the jwt keys url to which the requests for the current jwt token will be made
         *
         * Only set this jwt keys url if this library is not updated or the jwt keys url has changed
         * default: https://login.eveonline.com/oauth/jwks
         * @param m_jwt_keys_url
         */
        void set_jwt_keys_url(const std::string& m_jwt_keys_url) noexcept;

        /**
         * Get the current curl agent which is set to the header of a http request
         * @return The current curl agent
         */
        const std::string& get_curl_agent() const noexcept;

        /**
         * Set the curl agent which is set to the header of a http request
         *
         * You can change it to the current curl version you use but it is not mandatory
         * default: libcurl/7.69.0
         * @param m_curl_agent
         */
        void set_curl_agent(const std::string& m_curl_agent) noexcept;

        /**
         * Get the current auth_query url to which all querys will be made
         * @return The current auth_query url
         */
        const std::string& get_query_url() const noexcept;

        /**
         * Set the current auth_query url to which all querys will be made
         *
         * Only set this query url if this library is not updated or the auth_query url has changed
         * default: https://esi.evetech.net/latest/
         * @param m_query_url
         */
        void set_query_url(const std::string& m_query_url) noexcept;

        /**
         * Get the current response type parameter which is set in an authorization post request
         * @return The current response type parameter
         */
        const std::string& get_response_type_param() const noexcept;

        /**
         * Set the current response type parameter which is set in an authorization post request
         *
         * Only set this response type parameter if this library is not updated or the reponse type parameter has changed
         * default: response_type=
         * @param m_response_type_param
         */
        void set_response_type_param(const std::string& m_response_type_param) noexcept;

        /**
         * Ge the current redirect url parameter which is set in an authorization post request
         * @return The current redirect url parameter
         */
        const std::string& get_redirect_url_param() const noexcept;

        /**
         * Set the current redirect url parameter which is set in an authorization post request
         *
         * Only set this redirect url parameter if this library is not updated or the redirect url parameter has changed
         * default: redirect_uri=
         * @param m_redirect_url_param
         */
        void set_redirect_url_param(const std::string& m_redirect_url_param) noexcept;

        /**
         * Get the current client_id parameter which is set in an authorization post request
         * @return The current client_id parameter
         */
        const std::string& get_client_id_param() const noexcept;

        /**
         * Set the current client_id parameter which is set in an authorization post request
         *
         * Only set this client_id parameter if this library is not updated or the client_id parameter has changed
         * default: client_id=
         * @param m_client_id_param
         */
        void set_client_id_param(const std::string& m_client_id_param) noexcept;

        /**
         * Get the current scope parameter which is set in an authorization post request
         * @return The current scope parameter
         */
        const std::string& get_scope_param() const noexcept;

        /**
         * Set the current scope parameter which is set in an authorization post request
         *
         * Only set this scope parameter if this library is not updated or the scope parameter has changed
         * default: scope=
         * @param m_scope_param
         */
        void set_scope_param(const std::string& m_scope_param) noexcept;

        /**
         * Get the current state parameter which is set in an authorization post request
         * @return The current state parameter
         */
        const std::string& get_state_param() const noexcept;

        /**
         * Set the current state parameter which is set in an authorization post request
         *
         * Only set this state parameter if this library is not updated or the state parameter has changed
         * default: state=
         * @param m_state_param
         */
        void set_state_param(const std::string& m_state_param) noexcept;

        /**
         * Get the current code challenge parameter which is set in an authorization post request
         * @return The current code challenge parameter
         */
        const std::string& get_code_challenge_param() const noexcept;

        /**
         * Set the current code challenge parameter which is set in an authorization post request
         *
         * Only set this code challenge parameter if this library is not updated or the code challenge parameter has changed
         * default: code_challenge=
         * @param m_code_challenge_param
         */
        void set_code_challenge_param(const std::string& m_code_challenge_param) noexcept;

        /**
         * Get the current code challenge method parameter which is set in an authorization post request
         * @return The current code challenge method parameter
         */
        const std::string& get_code_challenge_method_param() const noexcept;

        /**
         * Set the current code challenge method parameter which is set in an authorization post request
         *
         * Only set this code challenge method parameter if this library is not updated or the code challenge method parameter has changed
         * default: code_challenge_method=
         * @param m_code_challenge_method_param
         */
        void set_code_challenge_method_param(const std::string& m_code_challenge_method_param) noexcept;

        /**
         * Get the current grant type parameter which is set in an authorization post request
         * @return The current grant type parameter
         */
        const std::string& get_grant_type_param() const noexcept;

        /**
         * Set the current grant type parameter which is set in an authorization post request
         *
         * Only set this grant type parameter if this library is not updated or the grant type parameter has changed
         * default: grant_type=
         * @param m_grant_type_param
         */
        void set_grant_type_param(const std::string& m_grant_type_param) noexcept;

        /**
         * Get the current code parameter which is set in an authorization post request
         * @return The current code parameter
         */
        const std::string& get_code_param() const noexcept;

        /**
         * Set the current code parameter which is set in an authorization post request
         *
         * Only set this code parameter if this library is not updated or the code parameter has changed
         * default: code=
         * @param m_code_param
         */
        void set_code_param(const std::string& m_code_param) noexcept;

        /**
         * Get the current code verifier parameter which is set in an authorization post request
         * @return The current code verifier parameter
         */
        const std::string& get_code_verifier_param() const noexcept;

        /**
         * Set the current code verifier parameter which is set in an authorization post request
         *
         * Only set this code verifier parameter if this library is not updated or the code verifier parameter has changed
         * default: code_verifier=
         * @param m_code_verifier_param
         */
        void set_code_verifier_param(const std::string& m_code_verifier_param) noexcept;

        /**
         * Get the current refresh token parameter which is set in an authorization post request
         * @return The current refresh token parameter
         */
        const std::string& get_refresh_token_param() const noexcept;

        /**
         * Set the current refresh token parameter which is set in an authorization post request
         *
         * Only set this refresh token parameter if this library is not updated or the refresh token parameter has changed
         * default: refresh_token=
         * @param m_refresh_token_param
         */
        void set_refresh_token_param(const std::string& m_refresh_token_param) noexcept;

        /**
         * Get the currently set state value which will be set to an authorization post request
         * @return The current state value
         */
        const std::string& get_state_val() const noexcept;

        /**
         * Set the current state value which will be set to an authorization post request
         *
         * Only set this state value if this library is not updated or the state value has changed
         * default: unique-state
         * @param m_state_val
         */
        void set_state_val(const std::string& m_state_val) noexcept;

        /**
         * Get the currently set code challenge method value which will be set to an authorization post request
         * @return The current code challenge method value
         */
        const std::string& get_code_challenge_method_val() const noexcept;

        /**
         * Set the current code challenge method value which will be set to an authorization post request
         *
         * Only set this code challenge method value if this library is not updated or the code challenge method value has changed
         * default: S256
         * @param m_code_challenge_method_val
         */
        void set_code_challenge_method_val(const std::string& m_code_challenge_method_val) noexcept;

        /**
         * Get the currently set redirect url value which will be set to an authorization post request
         * @return The current redirect url value
         */
        const std::string& get_redirect_url_val() const noexcept;

        /**
         * Set the current code challenge method value which will be set to an authorization post request
         *
         * You may want to set this value in order to change the redirect value to a different value which suits your application
         * The redirect url has to be url safe
         * default: https%3A%2F%2Flocalhost%2Fcallback%2F
         * @param m_redirect_url_val
         */
        void set_redirect_url_val(const std::string& m_redirect_url_val) noexcept;

        /**
         * Get the currently set response type value which will be set to an authorization post request
         * @return The current response type value
         */
        const std::string& get_response_type_val() const noexcept;

        /**
         * Set the current response type value which will be set to an authorization post request
         *
         * Only set this response type value if this library is not updated or the response type value has changed
         * default: code
         * @param m_response_type_val
         */
        void set_response_type_val(const std::string& m_response_type_val) noexcept;

        /**
         * Get the currently set grant type value which will be set to an authorization post request
         * @return The current grant type value
         */
        const std::string& get_grant_type_val() const noexcept;

        /**
         * Set the current code grant type value which will be set to an authorization post request
         *
         * Only set this code grant type value if this library is not updated or the code grant type value has changed
         * default: authorization_code
         * @param m_grant_type_val
         */
        void set_grant_type_val(const std::string& m_grant_type_val) noexcept;

        /**
         * Get the currently set refresh grant type value which will be set to an authorization post request
         * @return The current refresh grant type value
         */
        const std::string& get_grant_type_refresh_val() const noexcept;

        /**
         * Set the current refresh grant type value which will be set to an authorization post request
         *
         * Only set this refresh grant type value if this library is not updated or the refresh grant type value has changed
         * default: refresh_token
         * @param m_grant_type_refresh_val
         */
        void set_grant_type_refresh_val(const std::string& m_grant_type_refresh_val) noexcept;

        /**
         * Get the current cacert path which is necessary to make https requests
         * @return The current cacert path
         */
        const std::string& get_cacert_path() const noexcept;

        /**
         * Set the absolute path to the cacert which is necessary to make https requests
         *
         * You have to set the path to the cacert if you are on Windows otherwise the requests will fail and throw
         * an EVEAuthException
         * You can use the certificate in the directory of this library or download it from somewhere else
         * @param m_cacert_path
         */
        void set_cacert_path(const std::string& m_cacert_path) noexcept;

        /**
         * Get the current interval which specifies when the token will be refreshed
         * @return The current refresh interval
         */
        const int& get_refresh_interval() const noexcept;

        /**
         * Set the interval which specifies when the token will be refresh
         *
         * As for now, the token is valid for 20 Minutes, i.e. 1200 seconds
         * You may want to change this value to retrieve the refresh token earlier or later
         * As for now, it is not necessary to change this value
         * default: 900
         * @param m_refresh_interval
         */
        void set_refresh_interval(const int& m_refresh_interval) noexcept;

        /* Predefined static parameters */
    public:
        static constexpr const char* CURL_AGENT = "libcurl/7.69.0";

        /* Predefined auth_query parameter and values for login */
    private:
        std::string host = "login.eveonline.com";
        std::string content_type = "application/x-www-form-urlencoded";
        std::string base_url = "https://login.eveonline.com/v2/oauth/authorize/";
        std::string request_url = "https://login.eveonline.com/v2/oauth/token";
        std::string jwt_keys_url = "https://login.eveonline.com/oauth/jwks";
        std::string curl_agent = "libcurl/7.69.0";
        std::string query_url = "https://esi.evetech.net/latest/";

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
        std::string refresh_token_param = "refresh_token=";

        std::string state_val = "unique-state";
        std::string code_challenge_method_val = "S256";
        std::string redirect_url_val = "https%3A%2F%2Flocalhost%2Fcallback%2F";
        std::string response_type_val = "code";
        std::string grant_type_val = "authorization_code";
        std::string grant_type_refresh_val = "refresh_token";

        std::string cacert_path = "";
        int refresh_interval = 900;
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

    /**
     * Creates an error message by the given list of strings
     * @param list The list of strings
     * @return A string which consists out of the appended given strings from the list
     */
    std::string make_err_msg(std::initializer_list<std::string> list) noexcept;

    /**
     * Splits the given string by the given delimiter and saves the tokens within a vector
     * @param s The string which will be split
     * @param d The delimiter
     * @return The vector with the tokens
     */
    std::vector<std::string> split_by_delimiter(std::string& s, const std::string& d) noexcept;
}