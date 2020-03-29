/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Token.h"
#include "encodings/Base64.h"

EVEAuth::Token::Token() noexcept(false) = default;

void EVEAuth::Token::decode_access_token() noexcept
{
    int header_end = access_token.find('.');
    if (header_end == std::string::npos) {
        return;
    }

    int payload_end = access_token.find('.', header_end + 1);
    if (payload_end == std::string::npos) {
        return;
    }

    int signature_end = access_token.find('.', payload_end + 1);
    if (signature_end == std::string::npos) {
        return;
    }

    std::string header_enc = access_token.substr(0, header_end);
    std::string payload_enc = access_token.substr(header_end + 1, payload_end - header_end - 1);
    std::string signature_enc = access_token.substr(payload_end + 1);

    header = EVEAuth::Base64(header_enc).decode_url_safe();
    payload = EVEAuth::Base64(payload_enc).decode_url_safe();
    signature = EVEAuth::Base64(signature_enc).decode_url_safe();
}

const std::string& EVEAuth::Token::get_access_token() const noexcept
{
    return access_token;
}

void EVEAuth::Token::set_access_token(const std::string& m_access_token) noexcept
{
    access_token = m_access_token;
}

const std::string& EVEAuth::Token::get_token_type() const noexcept
{
    return token_type;
}

void EVEAuth::Token::set_token_type(const std::string& m_token_type) noexcept
{
    token_type = m_token_type;
}

const std::string& EVEAuth::Token::get_refresh_token() const noexcept
{
    return refresh_token;
}

void EVEAuth::Token::set_refresh_token(const std::string& m_refresh_token) noexcept
{
    refresh_token = m_refresh_token;
}

const int& EVEAuth::Token::get_expires_in() const noexcept
{
    return expires_in;
}

void EVEAuth::Token::set_expires_in(const int &m_expires_in) noexcept
{
    expires_in = m_expires_in;
}
