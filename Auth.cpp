/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Auth.h"

/* Includes for sha256 generation */
#include "iomanip"
#include "openssl/evp.h"

EVEAuth::Auth::Auth(std::string &client_id) : client_id(std::move(client_id)) {

}

std::string EVEAuth::generate_hash(const std::string& s) noexcept
{
    /* Allocates and returns a digest context */
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    if (context == nullptr) return "";

    /* Sets up digest context ctx to use a digest type and its standard implementation (nullptr) */
    int checkInit = EVP_DigestInit_ex(context, EVP_sha256(), nullptr);

    /* checkInit 1 is success, 0 is failure */
    if (checkInit == 0) return "";

    /* Hashes s.length() bytes of data at s.c_str() into the digest context */
    int checkUpdate = EVP_DigestUpdate(context, s.c_str(), s.length());

    /* checkUpdate 1 is success, 0 is failure */
    if (checkUpdate == 0) return "";

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    /* Retrieves the digest value from context and places it in hash
     * Writes the number of bytes written into lengthOfHash */
    int checkFinal = EVP_DigestFinal_ex(context, hash, &lengthOfHash);

    /* checkFinal 1 is success, 0 is failure */
    if (checkFinal == 0) return "";

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
    }

    return ss.str();
}
