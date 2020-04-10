/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Auth.h"

/* Includes for sha256 generation */
#include "iomanip"
#include "openssl/evp.h"
#include "encodings/Base64.h"

/* Include for generating code challenge */
#include <random>
#include <algorithm>

/* Includes for token handling */
#include "curl/curl.h"
#include "utils/picojson.h"
#include <cstring>

/* Includes for creating public pem key and token verification */
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "utils/jwt.h"

EVEAuth::AuthException::AuthException(std::string message, int error_code) noexcept : message(std::move(message)), error_code(error_code)
{
}

const char* EVEAuth::AuthException::what() const noexcept
{
    return message.c_str();
}

const int& EVEAuth::AuthException::get_error_code() const noexcept
{
    return error_code;
}

EVEAuth::Auth::Auth(std::string &client_id, std::string& scope_val) noexcept : client_id(std::move(client_id)), scope_val(std::move(scope_val))
{
    // Handle winsock stuff
    curl_global_init(CURL_GLOBAL_ALL);
    token = new EVEAuth::Token();
}

EVEAuth::Auth::~Auth() noexcept
{
    curl_global_cleanup();
    delete token;
}

std::string& EVEAuth::Auth::generate_auth_url() noexcept (false)
{
    try {
        generate_code_challenge();
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }

    if (authentication_url.empty()) {
        put_url_together();
    }

    return authentication_url;
}

void EVEAuth::Auth::put_url_together() noexcept
{
    std::stringstream ss;

    ss << base_url;
    ss << "?" << response_type_param << response_type_val;
    ss << "&" << redirect_url_param << redirect_url_val;
    ss << "&" << client_id_param << client_id;
    ss << "&" << scope_param << scope_val;
    ss << "&" << state_param << state_val;
    ss << "&" << code_challenge_param << code_challenge;
    ss << "&" << code_challenge_method_param << code_challenge_method_val;

    authentication_url = ss.str();
}

void EVEAuth::Auth::generate_code_challenge() noexcept(false)
{
    // Generate PKCE_BYTE_NUM of random bytes
    std::random_device random_device;
    std::vector<unsigned char> random_data(PKCE_BYTE_NUM);
    for (unsigned char& i : random_data)
    {
        i = static_cast<unsigned char>(random_device());
    }

    // Encode the raw random bytes to base64-url-safe
    EVEAuth::Base64 base64(reinterpret_cast<char*> (random_data.data()));
    std::string encoded_random_bytes = base64.encode_url_safe();

    // Hash the given code challenge with sha256
    std::string hashed_enc_rand_bytes;
    try {
        hashed_enc_rand_bytes = EVEAuth::generate_hash(encoded_random_bytes);
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }

    // Encode hashed code challenge
    EVEAuth::Base64 hashed_bade64(hashed_enc_rand_bytes);
    std::string enc_hashed_bytes = hashed_bade64.encode_url_safe();

    enc_hashed_bytes.erase(std::remove(enc_hashed_bytes.begin(),enc_hashed_bytes.end(), '='), enc_hashed_bytes.end());
    code_challenge = enc_hashed_bytes;
    code_verifier = encoded_random_bytes;
}

std::string EVEAuth::generate_hash(const std::string& s) noexcept(false)
{
    std::vector<unsigned char> hashed{};

    // Allocates and returns a digest context
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) throw AuthException(ERR_HASH_CTX, ERR_HASH_CTX_CODE);

    // Sets up digest context ctx to use a digest type and its standard implementation (nullptr)
    int check_init = EVP_DigestInit_ex(context, EVP_sha256(), nullptr);

    // check_init 1 is success, 0 is failure
    if (check_init == 0) throw AuthException(ERR_HASH_INIT, ERR_HASH_INIT_CODE);

    // Hashes s.length() bytes of data at s.c_str() into the digest context
    int check_update = EVP_DigestUpdate(context, s.c_str(), s.length());

    // check_update 1 is success, 0 is failure
    if (check_update == 0) throw AuthException(ERR_HASH_UPDATE, ERR_HASH_UPDATE_CODE);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;

    /* Retrieves the digest value from context and places it in hash
     * Writes the number of bytes written into length_of_hash */
    int check_final = EVP_DigestFinal_ex(context, hash, &length_of_hash);

    // check_final 1 is success, 0 is failure
    if (check_final == 0) throw AuthException(ERR_HASH_FINAL, ERR_HASH_FINAL_CODE);

    std::stringstream ss;
    for(unsigned int i = 0; i < length_of_hash; ++i)
    {
        ss << hash[i];
    }

    return ss.str();
}

std::string EVEAuth::generate_pem_key(const std::string& n, const std::string& e) noexcept
{
    std::string tmp_n = n;
    std::string tmp_e = e;
    EVEAuth::fix_padding(tmp_n);
    EVEAuth::fix_padding(tmp_e);

    std::string dec_modulus = EVEAuth::Base64(tmp_n).decode_url_safe();
    std::string dec_exponent = EVEAuth::Base64(tmp_e).decode_url_safe();

    // Cast modulus and exponent to BIGNUM*
    BIGNUM* modulus = BN_bin2bn(reinterpret_cast<const unsigned char*>(dec_modulus.data()), dec_modulus.size(), nullptr);
    BIGNUM* exponent = BN_bin2bn(reinterpret_cast<const unsigned char*>(dec_exponent.data()), dec_exponent.size(), nullptr);

    // Make RSA key
    RSA* rr = RSA_new();
    RSA_set0_key(rr, modulus, exponent, nullptr);

    // Create stream in memory
    BIO* mem = BIO_new(BIO_s_mem());

    // Write key to memory stream
    PEM_write_bio_RSA_PUBKEY(mem, rr);

    // Reads key out of memory
    char buffer[PEM_BUFF_SIZE];
    memset(buffer, 0, PEM_BUFF_SIZE);
    BIO_read(mem, buffer, PEM_BUFF_SIZE - 1);

    BIO_free(mem);
    return std::string(buffer);
}

void EVEAuth::Auth::verify_token() noexcept(false)
{
    send_jwt_request();
    std::string jwt_keys_response = download_response;
    picojson::value val;
    std::string parse_error = picojson::parse(val, jwt_keys_response);
    if (!parse_error.empty()) {
        throw AuthException(ERR_VFT_PICOJSON_PARSE, ERR_VFT_PICOJSON_PARSE_CODE);
    }

    // We want the EVEAuth::Token::algorithm and its related values
    picojson::array list = val.get("keys").get<picojson::array>();
    std::string algorithm;
    std::string e;
    std::string kid;
    std::string kty;
    std::string n;
    for (picojson::array::iterator iter = list.begin(); iter != list.end(); ++iter) {
        if ((*iter).get("alg").get<std::string>() == EVEAuth::Token::algorithm) {
            algorithm = (*iter).get("alg").get<std::string>();
            e = (*iter).get("e").get<std::string>();
            kty = (*iter).get("kty").get<std::string>();
            kid = (*iter).get("kid").get<std::string>();
            n = (*iter).get("n").get<std::string>();
        }
    }

    // Parse tokens decoded header
    picojson::value header_val;
    std::string header_parse_error = picojson::parse(header_val, token->get_header());
    if (!header_parse_error.empty()) {
        throw AuthException(ERR_VFT_PICOJSON_PARSE, ERR_VFT_PICOJSON_PARSE_CODE);
    }

    // Check if the decoded token header algorithm matches EVEAuth::Token::algorithm
    if (header_val.get("alg").get<std::string>() != EVEAuth::Token::algorithm) {
        throw AuthException(ERR_VFT_PICOJSON_PARSE, ERR_VFT_PICOJSON_PARSE_CODE);
    }

    // Generate public key in pem format
    std::string pem_key = EVEAuth::generate_pem_key(n, e);

    auto jwt_decoded = jwt::decode(token->get_access_token());
    auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256(pem_key, "", "", "")).with_issuer(host);
    try {
        verifier.verify(jwt_decoded);
    } catch (jwt::token_verification_exception& e) {
        std::string tmp = std::string(ERR_VFT_VRF) + " " + e.what();
        throw EVEAuth::AuthException(tmp, ERR_VFT_VRF_CODE);
    }
}

void EVEAuth::Auth::send_jwt_request() noexcept(false)
{
    CURL* curl;
    CURLcode res;

    struct MemoryStruct chu;
    chu.memory = (char*) malloc(1);
    chu.size = 0;

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* chunk = nullptr;
        std::string h_str = "Host: " + host;
        std::string c_type_str = "Content-Type: " + content_type;
        chunk = curl_slist_append(chunk, c_type_str.c_str());
        chunk = curl_slist_append(chunk, h_str.c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_URL, jwt_keys_url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &chu);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, curl_agent.c_str());
#ifdef WIN
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert_path.c_str());
#endif

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::string tmp = std::string(ERR_CEP_JWT_REQ) + " " + curl_easy_strerror(res);
            throw AuthException(tmp, ERR_CEP_JWT_REQ_CODE);
        } else {
            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 200) {
                download_response = std::string(chu.memory);
            } else {
                std::string tmp = std::string(ERR_CEP_JWT_REQ_RSP) + " Code: " + std::to_string(responseCode);
                throw AuthException(tmp, ERR_CEP_JWT_REQ_RSP_CODE);
            }
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
}

void EVEAuth::Auth::send_token_request() noexcept(false)
{
    CURL* curl;
    CURLcode res;

    struct MemoryStruct chu;
    chu.memory = (char*) malloc(1);
    chu.size = 0;

    // Make post value string
    std::stringstream ss;
    ss << grant_type_param << grant_type_val;
    ss << "&" << client_id_param << client_id;
    ss << "&" << code_param << code_val;
    ss << "&" << code_verifier_param << code_verifier;
    std::string request_str = ss.str();

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* chunk = nullptr;
        std::string h_str = "Host: " + host;
        std::string c_type_str = "Content-Type: " + content_type;
        chunk = curl_slist_append(chunk, c_type_str.c_str());
        chunk = curl_slist_append(chunk, h_str.c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_URL, request_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, EVEAuth::write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &chu);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, curl_agent.c_str());
#ifdef WIN
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert_path.c_str());
#endif

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::string tmp = std::string(ERR_CEP_TOKEN_REQ) + " " + curl_easy_strerror(res);
            throw AuthException(tmp, ERR_CEP_TOKEN_REQ_CODE);
        } else {
            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 200) {
                download_response = std::string(chu.memory);
            } else {
                std::string tmp = std::string(ERR_CEP_TOKEN_REQ_RSP) + " Code: " + std::to_string(responseCode);
                throw AuthException(tmp, ERR_CEP_TOKEN_REQ_RSP_CODE);
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
}

void EVEAuth::Auth::parse_token_request() noexcept(false)
{
    std::string token_response = download_response;
    picojson::value val;
    std::string parse_error;
    try {
        parse_error = picojson::parse(val, token_response);
    } catch (std::runtime_error& e) {
        std::string tmp = std::string(ERR_PTR_PICOJSON) + " " + e.what();
        throw AuthException(tmp, ERR_PTR_PICOJSON_CODE);
    }

    std::string access_token;
    if (!parse_error.empty()) {
        throw AuthException(ERR_PTR_PICOJSON_PARSE, ERR_PTR_PICOJSON_PARSE_CODE);
    }

    access_token = val.get("access_token").get<std::string>();
    int expires_in = val.get("expires_in").get<double>();
    std::string token_type = val.get("token_type").get<std::string>();
    std::string refresh_token = val.get("refresh_token").get<std::string>();

    if (!access_token.empty() && !token_type.empty() && !refresh_token.empty() && expires_in > 0) {
        token->set_access_token(access_token);
        token->set_token_type(token_type);
        token->set_refresh_token(refresh_token);
        token->set_expires_in(expires_in);
    }
}

void EVEAuth::Auth::refresh_token() noexcept(false)
{
    try {
        send_refresh_request();
        parse_token_request();
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }

    token->decode_access_token();
    try {
        verify_token();
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }
}

void EVEAuth::Auth::send_refresh_request() noexcept(false)
{
    CURL* curl;
    CURLcode res;

    struct MemoryStruct chu;
    chu.memory = (char*) malloc(1);
    chu.size = 0;

    // Make post value string
    std::stringstream ss;
    ss << grant_type_param << grant_type_refresh_val;
    ss << "&" << refresh_token_param << token->get_refresh_token();
    ss << "&" << client_id_param << client_id;
    std::string request_str = ss.str();

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* chunk = nullptr;
        std::string h_str = "Host: " + host;
        std::string c_type_str = "Content-Type: " + content_type;
        chunk = curl_slist_append(chunk, c_type_str.c_str());
        chunk = curl_slist_append(chunk, h_str.c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_URL, request_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, EVEAuth::write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &chu);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, curl_agent.c_str());
#ifdef WIN
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert_path.c_str());
#endif

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::string tmp = std::string(ERR_RET_TOKEN_REQ) + " " + curl_easy_strerror(res);
            throw AuthException(tmp, ERR_RET_TOKEN_REQ_CODE);
        } else {
            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 200) {
                download_response = std::string(chu.memory);
            } else {
                std::string tmp = std::string(ERR_RET_TOKEN_RSP) + " Code: " + std::to_string(responseCode);
                throw AuthException(tmp, ERR_RET_TOKEN_RSP_CODE);
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
}

EVEAuth::Token* EVEAuth::Auth::start() noexcept(false)
{
    // If there is not code value set, return nullptr
    if (code_val.empty()) {
        return nullptr;
    }

    try {
        send_token_request();
        parse_token_request();
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }
    token->decode_access_token();
    try {
        verify_token();
    } catch (AuthException& e) {
        throw AuthException(e.what(), e.get_error_code());
    }
    return token;
}

static size_t EVEAuth::write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*) userp;

    char* ptr = (char*) realloc(mem->memory, mem->size + real_size + 1);
    if(ptr == nullptr) {
        printf("not enough memory\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->memory[mem->size] = 0;

    return real_size;
}

const std::string& EVEAuth::Auth::get_scope_val() const noexcept
{
    return scope_val;
}

const std::string& EVEAuth::Auth::get_client_id() const noexcept
{
    return client_id;
}

const std::string& EVEAuth::Auth::get_code_val() const noexcept
{
    return code_val;
}

void EVEAuth::Auth::set_code_val(const std::string& m_code_val) noexcept
{
    code_val = m_code_val;
}

const std::string& EVEAuth::Auth::get_authentication_url() const noexcept
{
    return authentication_url;
}

void EVEAuth::Auth::set_authentication_url(const std::string& m_authentication_url) noexcept
{
    authentication_url = m_authentication_url;
}

const std::string& EVEAuth::Auth::get_host() const noexcept
{
    return host;
}

void EVEAuth::Auth::set_host(const std::string& m_host) noexcept
{
    host = m_host;
}

const std::string& EVEAuth::Auth::get_content_type() const noexcept
{
    return content_type;
}

void EVEAuth::Auth::set_content_type(const std::string& m_content_type) noexcept
{
    content_type = m_content_type;
}

const std::string& EVEAuth::Auth::get_base_url() const noexcept
{
    return base_url;
}

void EVEAuth::Auth::set_base_url(const std::string& m_base_url) noexcept
{
    base_url = m_base_url;
}

const std::string& EVEAuth::Auth::get_request_url() const noexcept
{
    return request_url;
}

void EVEAuth::Auth::set_request_url(const std::string& m_request_url) noexcept
{
    request_url = m_request_url;
}

const std::string& EVEAuth::Auth::get_jwt_keys_url() const noexcept
{
    return jwt_keys_url;
}

void EVEAuth::Auth::set_jwt_keys_url(const std::string& m_jwt_keys_url) noexcept
{
    jwt_keys_url = m_jwt_keys_url;
}

const std::string& EVEAuth::Auth::get_curl_agent() const noexcept
{
    return curl_agent;
}

void EVEAuth::Auth::set_curl_agent(const std::string& m_curl_agent) noexcept
{
    curl_agent = m_curl_agent;
}

const std::string& EVEAuth::Auth::get_response_type_param() const noexcept
{
    return response_type_param;
}

void EVEAuth::Auth::set_response_type_param(const std::string& m_response_type_param) noexcept
{
    response_type_param = m_response_type_param;
}

const std::string& EVEAuth::Auth::get_redirect_url_param() const noexcept
{
    return redirect_url_param;
}

void EVEAuth::Auth::set_redirect_url_param(const std::string& m_redirect_url_param) noexcept
{
    redirect_url_param = m_redirect_url_param;
}

const std::string& EVEAuth::Auth::get_client_id_param() const noexcept
{
    return client_id_param;
}

void EVEAuth::Auth::set_client_id_param(const std::string& m_client_id_param) noexcept
{
    client_id_param = m_client_id_param;
}

const std::string& EVEAuth::Auth::get_scope_param() const noexcept
{
    return scope_param;
}

void EVEAuth::Auth::set_scope_param(const std::string& m_scope_param) noexcept
{
    scope_param = m_scope_param;
}

const std::string& EVEAuth::Auth::get_state_param() const noexcept
{
    return state_param;
}

void EVEAuth::Auth::set_state_param(const std::string& m_state_param) noexcept
{
    state_param = m_state_param;
}

const std::string& EVEAuth::Auth::get_code_challenge_param() const noexcept
{
    return code_challenge_param;
}

void EVEAuth::Auth::set_code_challenge_param(const std::string& m_code_challenge_param) noexcept
{
    code_challenge_param = m_code_challenge_param;
}

const std::string& EVEAuth::Auth::get_code_challenge_method_param() const noexcept
{
    return code_challenge_method_param;
}

void EVEAuth::Auth::set_code_challenge_method_param(const std::string& m_code_challenge_method_param) noexcept
{
    code_challenge_method_param = m_code_challenge_method_param;
}

const std::string& EVEAuth::Auth::get_grant_type_param() const noexcept
{
    return grant_type_param;
}

void EVEAuth::Auth::set_grant_type_param(const std::string& m_grant_type_param) noexcept
{
    grant_type_param = m_grant_type_param;
}

const std::string& EVEAuth::Auth::get_code_param() const noexcept
{
    return code_param;
}

void EVEAuth::Auth::set_code_param(const std::string& m_code_param) noexcept
{
    code_param = m_code_param;
}

const std::string& EVEAuth::Auth::get_code_verifier_param() const noexcept
{
    return code_verifier_param;
}

void EVEAuth::Auth::set_code_verifier_param(const std::string& m_code_verifier_param) noexcept
{
    code_verifier_param = m_code_verifier_param;
}

const std::string& EVEAuth::Auth::get_state_val() const noexcept
{
    return state_val;
}

void EVEAuth::Auth::set_state_val(const std::string& m_state_val) noexcept
{
    state_val = m_state_val;
}

const std::string& EVEAuth::Auth::get_code_challenge_method_val() const noexcept
{
    return code_challenge_method_val;
}

void EVEAuth::Auth::set_code_challenge_method_val(const std::string& m_code_challenge_method_val) noexcept
{
    code_challenge_method_val = m_code_challenge_method_val;
}

const std::string& EVEAuth::Auth::get_redirect_url_val() const noexcept
{
    return redirect_url_val;
}

void EVEAuth::Auth::set_redirect_url_val(const std::string& m_redirect_url_val) noexcept
{
    redirect_url_val = m_redirect_url_val;
}

const std::string& EVEAuth::Auth::get_response_type_val() const noexcept
{
    return response_type_val;
}

void EVEAuth::Auth::set_response_type_val(const std::string& m_response_type_val) noexcept
{
    response_type_val = m_response_type_val;
}

const std::string& EVEAuth::Auth::get_grant_type_val() const noexcept
{
    return grant_type_val;
}

void EVEAuth::Auth::set_grant_type_val(const std::string& m_grant_type_val) noexcept
{
    grant_type_val = m_grant_type_val;
}

const std::string& EVEAuth::Auth::get_grant_type_refresh_val() const noexcept
{
    return grant_type_refresh_val;
}

void EVEAuth::Auth::set_grant_type_refresh_val(const std::string& m_grant_type_refresh_val) noexcept
{
    grant_type_refresh_val = m_grant_type_refresh_val;
}

const std::string& EVEAuth::Auth::get_refresh_token_param() const noexcept
{
    return refresh_token_param;
}

void EVEAuth::Auth::set_refresh_token_param(const std::string& m_refresh_token_param) noexcept
{
    refresh_token_param = m_refresh_token_param;
}

const std::string& EVEAuth::Auth::get_cacert_path() const noexcept
{
    return cacert_path;
}

void EVEAuth::Auth::set_cacert_path(const std::string& m_cacert_path) noexcept
{
    cacert_path = m_cacert_path;
}
