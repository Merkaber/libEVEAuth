/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"

namespace EVEAuth {
    class Auth {
    public:
        Auth(std::string& client_id);

    private:
        const std::string client_id;
    };
}