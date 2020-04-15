/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include <iostream>
#include "Token.h"
#include "encodings/Base64.h"
#include "utils/picojson.h"
#include "Auth.h"

const std::string EVEAuth::Token::algorithm = "RS256";

EVEAuth::Token::Token() noexcept(false) = default;

void EVEAuth::Token::decode_access_token() noexcept(false)
{
    int header_end = access_token.find('.');
    if (header_end == std::string::npos) {
        return;
    }

    int payload_end = access_token.find('.', header_end + 1);
    if (payload_end == std::string::npos) {
        return;
    }

    std::string header_enc = access_token.substr(0, header_end);
    std::string payload_enc = access_token.substr(header_end + 1, payload_end - header_end - 1);
    std::string signature_enc = access_token.substr(payload_end + 1);
    
    EVEAuth::fix_padding(header_enc);
    EVEAuth::fix_padding(payload_enc);
    EVEAuth::fix_padding(signature_enc);

    header = EVEAuth::Base64(header_enc).decode_url_safe();
    payload = EVEAuth::Base64(payload_enc).decode_url_safe();
    signature = EVEAuth::Base64(signature_enc).decode_url_safe();

    try {
        parse_claims();
    } catch (EVEAuth::AuthException& e) {
        throw EVEAuth::AuthException{make_err_msg({F_DAT_NAME, e.what()}), e.get_error_code()};
    }
}

void EVEAuth::Token::parse_claims() noexcept(false)
{
    picojson::value val;
    std::string parse_error;
    try {
        parse_error = picojson::parse(val, payload);
    } catch (EVEAuth::AuthException& e) {
        throw EVEAuth::AuthException{make_err_msg({F_PC_NAME, ERR_PC_PICOJSON, e.what()}), ERR_PC_PICOJSON_CODE};
    }

    if (!parse_error.empty()) {
        throw EVEAuth::AuthException{make_err_msg({F_PC_NAME, ERR_PC_PICOJSON, parse_error}), ERR_PC_PICOJSON_CODE};
    }

    character_name = val.get("name").get<std::string>();
    std::string sub = val.get("sub").get<std::string>();
    std::vector<std::string> v = split_by_delimiter(sub, ":");
    character_id = v[2];
}

const std::string& EVEAuth::Token::get_header() const noexcept
{
    return header;
}

const std::string& EVEAuth::Token::get_base64_header() const noexcept
{
    return base64_header;
}

const std::string& EVEAuth::Token::get_payload() const noexcept
{
    return payload;
}

const std::string& EVEAuth::Token::get_base64_payload() const noexcept
{
    return base64_payload;
}

const std::string& EVEAuth::Token::get_signature() const noexcept
{
    return signature;
}

const std::string& EVEAuth::Token::get_base64_signature() const noexcept
{
    return base64_signature;
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

const std::string& EVEAuth::Token::get_character_id() const noexcept
{
    return character_id;
}

const std::string& EVEAuth::Token::get_character_name() const noexcept
{
    return character_name;
}
