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

const std::string& EVEAuth::Auth::getBaseUrl() const {
    return base_url;
}

void EVEAuth::Auth::setBaseUrl(const std::string& baseUrl) {
    base_url = baseUrl;
}

const std::string& EVEAuth::Auth::getRequestUrl() const {
    return request_url;
}

void EVEAuth::Auth::setRequestUrl(const std::string& requestUrl) {
    request_url = requestUrl;
}

const std::string& EVEAuth::Auth::getJwtKeysUrl() const {
    return jwt_keys_url;
}

void EVEAuth::Auth::setJwtKeysUrl(const std::string& jwtKeysUrl) {
    jwt_keys_url = jwtKeysUrl;
}

const std::string& EVEAuth::Auth::getResponseTypeParam() const {
    return response_type_param;
}

void EVEAuth::Auth::setResponseTypeParam(const std::string& responseTypeParam) {
    response_type_param = responseTypeParam;
}

const std::string& EVEAuth::Auth::getRedirectUrlParam() const {
    return redirect_url_param;
}

void EVEAuth::Auth::setRedirectUrlParam(const std::string& redirectUrlParam) {
    redirect_url_param = redirectUrlParam;
}

const std::string& EVEAuth::Auth::getClientIdParam() const {
    return client_id_param;
}

void EVEAuth::Auth::setClientIdParam(const std::string& clientIdParam) {
    client_id_param = clientIdParam;
}

const std::string& EVEAuth::Auth::getScopeParam() const {
    return scope_param;
}

void EVEAuth::Auth::setScopeParam(const std::string& scopeParam) {
    scope_param = scopeParam;
}

const std::string& EVEAuth::Auth::getStateParam() const {
    return state_param;
}

void EVEAuth::Auth::setStateParam(const std::string& stateParam) {
    state_param = stateParam;
}

const std::string& EVEAuth::Auth::getCodeChallengeParam() const {
    return code_challenge_param;
}

void EVEAuth::Auth::setCodeChallengeParam(const std::string& codeChallengeParam) {
    code_challenge_param = codeChallengeParam;
}

const std::string& EVEAuth::Auth::getCodeChallengeMethodParam() const {
    return code_challenge_method_param;
}

void EVEAuth::Auth::setCodeChallengeMethodParam(const std::string& codeChallengeMethodParam) {
    code_challenge_method_param = codeChallengeMethodParam;
}

const std::string& EVEAuth::Auth::getGrantTypeParam() const {
    return grant_type_param;
}

void EVEAuth::Auth::setGrantTypeParam(const std::string& grantTypeParam) {
    grant_type_param = grantTypeParam;
}

const std::string& EVEAuth::Auth::getCodeParam() const {
    return code_param;
}

void EVEAuth::Auth::setCodeParam(const std::string& codeParam) {
    code_param = codeParam;
}

const std::string& EVEAuth::Auth::getCodeVerifierParam() const {
    return code_verifier_param;
}

void EVEAuth::Auth::setCodeVerifierParam(const std::string& codeVerifierParam) {
    code_verifier_param = codeVerifierParam;
}

const std::string& EVEAuth::Auth::getStateVal() const {
    return state_val;
}

void EVEAuth::Auth::setStateVal(const std::string& stateVal) {
    state_val = stateVal;
}

const std::string& EVEAuth::Auth::getCodeChallengeMethodVal() const {
    return code_challenge_method_val;
}

void EVEAuth::Auth::setCodeChallengeMethodVal(const std::string& codeChallengeMethodVal) {
    code_challenge_method_val = codeChallengeMethodVal;
}

const std::string& EVEAuth::Auth::getRedirectUrlVal() const {
    return redirect_url_val;
}

void EVEAuth::Auth::setRedirectUrlVal(const std::string& redirectUrlVal) {
    redirect_url_val = redirectUrlVal;
}

const std::string& EVEAuth::Auth::getResponseTypeVal() const {
    return response_type_val;
}

void EVEAuth::Auth::setResponseTypeVal(const std::string& responseTypeVal) {
    response_type_val = responseTypeVal;
}

const std::string& EVEAuth::Auth::getGrantTypeVal() const {
    return grant_type_val;
}

void EVEAuth::Auth::setGrantTypeVal(const std::string& grantTypeVal) {
    grant_type_val = grantTypeVal;
}
