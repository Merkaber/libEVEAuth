/*
 * EVEAuth
 *
 * Copyright (c) 2019 Simon Piorecki
 */

#pragma once

#include "shared.h"

/*
 * The number of bytes which is necessary for the PKCE protocol
 * Specification: https://tools.ietf.org/html/rfc7636
 */
#define PKCE_BYTE_NUM 32

namespace EVEAuth {
    class Auth {
    public:
        explicit Auth(std::string& client_id) noexcept;

        void connect() noexcept;

    private:

        void generate_code_challenge() noexcept;

    private:
        const std::string client_id;

        std::string code_challenge = "";

        std::string code_verifier = "";

        /* Getter and setter for query parameters and values */
    public:
        const std::string& getBaseUrl() const;
        void setBaseUrl(const std::string& baseUrl);

        const std::string& getRequestUrl() const;
        void setRequestUrl(const std::string& requestUrl);

        const std::string& getJwtKeysUrl() const;
        void setJwtKeysUrl(const std::string& jwtKeysUrl);

        const std::string& getResponseTypeParam() const;
        void setResponseTypeParam(const std::string& responseTypeParam);

        const std::string& getRedirectUrlParam() const;
        void setRedirectUrlParam(const std::string& redirectUrlParam);

        const std::string& getClientIdParam() const;
        void setClientIdParam(const std::string& clientIdParam);

        const std::string& getScopeParam() const;
        void setScopeParam(const std::string& scopeParam);

        const std::string& getStateParam() const;
        void setStateParam(const std::string& stateParam);

        const std::string& getCodeChallengeParam() const;
        void setCodeChallengeParam(const std::string& codeChallengeParam);

        const std::string& getCodeChallengeMethodParam() const;
        void setCodeChallengeMethodParam(const std::string& codeChallengeMethodParam);

        const std::string& getGrantTypeParam() const;
        void setGrantTypeParam(const std::string& grantTypeParam);

        const std::string& getCodeParam() const;
        void setCodeParam(const std::string& codeParam);

        const std::string& getCodeVerifierParam() const;
        void setCodeVerifierParam(const std::string& codeVerifierParam);

        const std::string& getStateVal() const;
        void setStateVal(const std::string& stateVal);

        const std::string& getCodeChallengeMethodVal() const;
        void setCodeChallengeMethodVal(const std::string& codeChallengeMethodVal);

        const std::string& getRedirectUrlVal() const;
        void setRedirectUrlVal(const std::string& redirectUrlVal);

        const std::string& getResponseTypeVal() const;
        void setResponseTypeVal(const std::string& responseTypeVal);

        const std::string& getGrantTypeVal() const;
        void setGrantTypeVal(const std::string& grantTypeVal);

        /* Query parameter and values for login */
    private:
        std::string base_url = "https://login.eveonline.com/v2/oauth/authorize/";
        std::string request_url = "https://login.eveonline.com/v2/oauth/token";
        std::string jwt_keys_url = "https://login.eveonline.com/oauth/jwks";

        std::string response_type_param = "response_type=";
        std::string redirect_url_param = "redirect_uri=";
        std::string client_id_param = "client_id=";
        std::string scope_param = "scope=";
        std::string state_param = "state=";
        std::string code_challenge_param = "code_challenge=";
        std::string code_challenge_method_param = "code_challenge_method=";
        std::string grant_type_param = "grant_type=";
        std::string code_param = "code=";
        std::string code_verifier_param = "code_verifier=";

        std::string state_val = "unique-state";
        std::string code_challenge_method_val = "S256";
        std::string redirect_url_val = "https%3A%2F%2Flocalhost%2Fcallback%2F";
        std::string response_type_val = "code";
        std::string grant_type_val = "authorization_code";

    };

    /**
     * Generates the hash value of the given std::string s
     * @param s The given string
     * @return The hash value if successfully hashed, otherwise an empty std::string
     */
    std::string generate_hash(const std::string& s) noexcept;
}