# libEVEAuth

libEVEAuth is a simple library for authentication handling with the 
[EVE swagger interface](https://github.com/esi/esi-docs) 'ESI' for a native C++ application.

If you want to make a native C++ application... this library is for you.\
If you want to make a native C application... this library is **not** for you.

## I am currently working on...
... a proper build support. You have to get all 7 header files and the static library after building in order to link properly.

## How to use

If you want to know how the authentication flow works, read the [docs](https://github.com/esi/esi-docs).

After creating an ```EVEAuth::Auth``` object with the applications client_id and the related scope, the user
have to log into his account through the received url from ```auth.generate_auth_url();```. After login, the user will
be redirected to the localhost by default and the code value is received. You then have to retrieve the code value from the user
and set it to the auth object by calling ```auth.set_code_val(code_val);```. Now you can start the authorization flow
by calling ```auth.start();```. The authorization token will be refreshed every 900 seconds by default.

```c++
#include "Auth.h"

...

std::string client_id = "03e...168";
std::string scope = "esi-characters.read_blueprints.v1";

EVEAuth::Auth auth(client_id, scope);

std::cout << auth.generate_auth_url() << std::endl;

std::string code_val;

if (std::cin >> code_val) {
    auth.set_code_val(code_val);
    try {
        auth.start();
    } catch (EVEAuth::AuthException& e) {
        std::cout << e.get_error_code() << ": " << e.what() << std::endl;
    }
}

std::string q = "characters/" + auth.get_character_id() + "/blueprints/";

std::cout << auth.query(q) << std::endl;
```

#### Dependencies:
- c++11<
- [OpenSSL](https://www.openssl.org/)
- [libcurl](https://curl.haxx.se/libcurl/)

#### Third party libraries used:
- [picojson](https://github.com/kazuho/picojson) by Cybozu Labs, Inc. / Kazuho Oku
- [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) by Thalhammer

#### Building
I recommend using cmake but it is not necessary.

#### Linking
Since the library depends on [OpenSSL](https://www.openssl.org/) and [libcurl](https://curl.haxx.se/libcurl/) you need
to link against them properly. Linking on Linux is easy compared to windows.

##### Linux

On Linux you have to link against libcurl and openssl.

```sh
-EVEAuth -curl -OpenSSL::Crypto -Threads::Threads -dl
```

##### Windows

On Windows you also have to link against wldap32 ws2_32.

```sh
-EVEAuth -curl -OpenSSL::Crypto -Threads::Threads -dl -wldap32 -ws2_32
```



