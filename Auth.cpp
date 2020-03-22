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

EVEAuth::Auth::Auth(std::string &client_id) noexcept : client_id(std::move(client_id)) {

}

void EVEAuth::Auth::connect() noexcept
{
    generate_code_challenge();

    if (authentication_url.empty()) {
        generate_authentication_url();
    }
}

void EVEAuth::Auth::generate_authentication_url() noexcept
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

const std::string& EVEAuth::Auth::getBaseUrl() const noexcept {
    return base_url;
}

void EVEAuth::Auth::setBaseUrl(const std::string& baseUrl) noexcept {
    base_url = baseUrl;
}

const std::string& EVEAuth::Auth::getRequestUrl() const noexcept {
    return request_url;
}

void EVEAuth::Auth::setRequestUrl(const std::string& requestUrl) noexcept {
    request_url = requestUrl;
}

const std::string& EVEAuth::Auth::getJwtKeysUrl() const noexcept {
    return jwt_keys_url;
}

void EVEAuth::Auth::setJwtKeysUrl(const std::string& jwtKeysUrl) noexcept {
    jwt_keys_url = jwtKeysUrl;
}

const std::string& EVEAuth::Auth::getResponseTypeParam() const noexcept {
    return response_type_param;
}

void EVEAuth::Auth::setResponseTypeParam(const std::string& responseTypeParam) noexcept {
    response_type_param = responseTypeParam;
}

const std::string& EVEAuth::Auth::getRedirectUrlParam() const noexcept {
    return redirect_url_param;
}

void EVEAuth::Auth::setRedirectUrlParam(const std::string& redirectUrlParam) noexcept {
    redirect_url_param = redirectUrlParam;
}

const std::string& EVEAuth::Auth::getClientIdParam() const noexcept {
    return client_id_param;
}

void EVEAuth::Auth::setClientIdParam(const std::string& clientIdParam) noexcept {
    client_id_param = clientIdParam;
}

const std::string& EVEAuth::Auth::getScopeParam() const noexcept {
    return scope_param;
}

void EVEAuth::Auth::setScopeParam(const std::string& scopeParam) noexcept {
    scope_param = scopeParam;
}

const std::string& EVEAuth::Auth::getStateParam() const noexcept {
    return state_param;
}

void EVEAuth::Auth::setStateParam(const std::string& stateParam) noexcept {
    state_param = stateParam;
}

const std::string& EVEAuth::Auth::getCodeChallengeParam() const noexcept {
    return code_challenge_param;
}

void EVEAuth::Auth::setCodeChallengeParam(const std::string& codeChallengeParam) noexcept {
    code_challenge_param = codeChallengeParam;
}

const std::string& EVEAuth::Auth::getCodeChallengeMethodParam() const noexcept {
    return code_challenge_method_param;
}

void EVEAuth::Auth::setCodeChallengeMethodParam(const std::string& codeChallengeMethodParam) noexcept {
    code_challenge_method_param = codeChallengeMethodParam;
}

const std::string& EVEAuth::Auth::getGrantTypeParam() const noexcept {
    return grant_type_param;
}

void EVEAuth::Auth::setGrantTypeParam(const std::string& grantTypeParam) noexcept {
    grant_type_param = grantTypeParam;
}

const std::string& EVEAuth::Auth::getCodeParam() const noexcept {
    return code_param;
}

void EVEAuth::Auth::setCodeParam(const std::string& codeParam) noexcept {
    code_param = codeParam;
}

const std::string& EVEAuth::Auth::getCodeVerifierParam() const noexcept {
    return code_verifier_param;
}

void EVEAuth::Auth::setCodeVerifierParam(const std::string& codeVerifierParam) noexcept {
    code_verifier_param = codeVerifierParam;
}

const std::string& EVEAuth::Auth::getStateVal() const noexcept {
    return state_val;
}

void EVEAuth::Auth::setStateVal(const std::string& stateVal) noexcept {
    state_val = stateVal;
}

const std::string& EVEAuth::Auth::getCodeChallengeMethodVal() const noexcept {
    return code_challenge_method_val;
}

void EVEAuth::Auth::setCodeChallengeMethodVal(const std::string& codeChallengeMethodVal) noexcept {
    code_challenge_method_val = codeChallengeMethodVal;
}

const std::string& EVEAuth::Auth::getRedirectUrlVal() const noexcept {
    return redirect_url_val;
}

void EVEAuth::Auth::setRedirectUrlVal(const std::string& redirectUrlVal) noexcept {
    redirect_url_val = redirectUrlVal;
}

const std::string& EVEAuth::Auth::getResponseTypeVal() const noexcept {
    return response_type_val;
}

void EVEAuth::Auth::setResponseTypeVal(const std::string& responseTypeVal) noexcept {
    response_type_val = responseTypeVal;
}

const std::string& EVEAuth::Auth::getGrantTypeVal() const noexcept {
    return grant_type_val;
}

void EVEAuth::Auth::setGrantTypeVal(const std::string& grantTypeVal) noexcept {
    grant_type_val = grantTypeVal;
}
