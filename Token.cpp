/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Token.h"

EVEAuth::Token::Token(std::string& access_token) noexcept : access_token(std::move(access_token))
{

}

const std::string& EVEAuth::Token::get_access_token() const noexcept
{
    return access_token;
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
