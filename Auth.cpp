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
