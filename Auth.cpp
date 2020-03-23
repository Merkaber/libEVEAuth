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
#include <cstring>

EVEAuth::Auth::Auth(std::string &client_id) noexcept : client_id(std::move(client_id)) {

}

void EVEAuth::Auth::generate_auth_url() noexcept
{
    generate_code_challenge();

    if (authentication_url.empty()) {
        put_url_together();
    }
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

void EVEAuth::Auth::generate_code_challenge() noexcept
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
    std::string hashed_enc_rand_bytes = EVEAuth::generate_hash(encoded_random_bytes);

    // Encode hashed code challenge
    EVEAuth::Base64 hashed_bade64(hashed_enc_rand_bytes);
    std::string enc_hashed_bytes = hashed_bade64.encode_url_safe();

    enc_hashed_bytes.erase(std::remove(enc_hashed_bytes.begin(),enc_hashed_bytes.end(), '='), enc_hashed_bytes.end());
    code_challenge = enc_hashed_bytes;

    // Encode random again
    EVEAuth::Base64 enc_base64(encoded_random_bytes);
    std::string code_verifier_tmp = enc_base64.encode_url_safe();

    // Replace all occurrences of '=' with ''
    code_verifier_tmp.erase(std::remove(code_verifier_tmp.begin(), code_verifier_tmp.end(), '='), code_verifier_tmp.end());
    code_verifier = code_verifier_tmp;
}

std::string EVEAuth::generate_hash(const std::string& s) noexcept
{
    /* Allocates and returns a digest context */
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) return "";

    /* Sets up digest context ctx to use a digest type and its standard implementation (nullptr) */
    int check_init = EVP_DigestInit_ex(context, EVP_sha256(), nullptr);

    /* check_init 1 is success, 0 is failure */
    if (check_init == 0) return "";

    /* Hashes s.length() bytes of data at s.c_str() into the digest context */
    int check_update = EVP_DigestUpdate(context, s.c_str(), s.length());

    /* check_update 1 is success, 0 is failure */
    if (check_update == 0) return "";

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;

    /* Retrieves the digest value from context and places it in hash
     * Writes the number of bytes written into length_of_hash */
    int check_final = EVP_DigestFinal_ex(context, hash, &length_of_hash);

    /* check_final 1 is success, 0 is failure */
    if (check_final == 0) return "";

    std::stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
    }

    return ss.str();
}

void EVEAuth::Auth::verify_token() noexcept
{

}

void EVEAuth::Auth::send_token_request() noexcept
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

    // Handle winsock stuff
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* chunk = nullptr;
        std::string h_str = "Host :" + host;
        std::string c_type_str = "Content-Type: " + content_type;
        chunk = curl_slist_append(chunk, c_type_str.c_str());
        chunk = curl_slist_append(chunk, h_str.c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_URL, request_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, EVEAuth::write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &chu);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, curl_agent.c_str());

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_response = false;
            fprintf(stderr, "curl_easy_perform() failed: %s \n", curl_easy_strerror(res));
        } else {
            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 200) {
                curl_response = true;
                download_response = std::string(chu.memory);
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
    curl_global_cleanup();
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

const std::string& EVEAuth::Auth::get_code_val() const noexcept
{
    return code_val;
}

void EVEAuth::Auth::set_code_val(const std::string& m_code_val) noexcept
{
    code_val = m_code_val;
}

const std::string& EVEAuth::Auth::get_scope_val() const noexcept
{
    return scope_val;
}

void EVEAuth::Auth::set_scope_val(const std::string& m_scope_val) noexcept
{
    scope_val = m_scope_val;
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
