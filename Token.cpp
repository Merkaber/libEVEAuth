/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#include "Token.h"

EVEAuth::Token::Token(std::string& access_token) noexcept : access_token(std::move(access_token))
{

}