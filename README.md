# libEVEAuth 1.0.0

libEVEAuth is a simple library for authorization handling with the 
[EVE swagger interface](https://github.com/esi/esi-docs) 'ESI' for a native C++ application.

If you want to make a native C++ application... this library is for you.  
If you want to make a native C application... this library is **not** for you.

## How to use

If you want to know how the authorization flow works, read the [docs](https://github.com/esi/esi-docs).  
For doxygen documentation open ```/../../libEVEAuth/docs/html/index.php```

After creating an ```EVEAuth::Auth``` object with the applications client_id and the related scope, the user
have to log into his account through the received url from ```auth.generate_auth_url();```. After login, the user will
be redirected to the localhost by default and the code value is received. You then have to retrieve the code value from the redirect url
and set it to the auth object by calling ```auth.set_code_val(code_val);```. Now you can start the authorization flow
by calling ```auth.start();```. The authorization token will be refreshed every 900 seconds by default.

```c++
#include "EVEAuth/Auth.h"

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

try {
    std::cout << auth.auth_query(q, true) << std::endl;
} catch (EVEAuth::AuthException& e) {
    std::cout << e.get_error_code() << ": " << e.what() << std::endl;
}

...
```

On Windows you have to set the path to the cacert.pem file before starting authorization since Windows may lack the ssl certificates.
```c++
auth.set_cacert_path(path);
```

### Dependencies:
- c++11<
- [OpenSSL](https://www.openssl.org/)
- [libcurl](https://curl.haxx.se/libcurl/)

### Third party libraries used:
- [picojson](https://github.com/kazuho/picojson) by Cybozu Labs, Inc. / Kazuho Oku
- [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) by Thalhammer

### Building on Windows
I recommend using [MinGW_w64](http://mingw-w64.org/doku.php) and [CMake](https://cmake.org/) for building.  
  
Read this tutorial for installing with [msys2](https://www.msys2.org/).

#### Get libCurl and OpenSSL for linking
Start the command prompt ```C:\msys64\mingw64.exe``` and download the necessary files:

```
pacman -S openssl-devel
pacman -S curl
pacman -S libcurl
```

If the curl dll is missing, I recommend [downloading](https://curl.haxx.se/download.html) precompiled binaries for MinGW.
Inside ```../curl-x.xx.x-win64-mingw/bin``` you will find ```libcurl-x64.dll```. Copy the dll into ```C:\Windows\System32```.

#### Build this library with CMake

Inside ```/../../libEVEAuth```:

1. Make a build directory:  
```mkdir build```  
```cd build```

2. Configure files for MinGW (don't forget the 'full stops' at the end!):  
```cmake -G "MinGW Makefiles" ..```

3. Build and install:  
```cmake --build . --target install```

If you do not want that the library is installed in the predefined system directory, uncomment the CMAKE_INSTALL_PREFIX
to install the library into the source directory.

#### Linking
Since the library depends on [OpenSSL](https://www.openssl.org/) and [libcurl](https://curl.haxx.se/libcurl/) you need
to link against them properly. This includes linking with Threads too.
Have a look into the CMakeLists.txt of this project to see how you can link using CMake.

```
...

find_package(EVEAuth REQUIRED)

target_link_libraries(${PROJECT_NAME} EVEAuth ... )

...
```

On Windows you also have to link against wldap32 ws2_32:

```
target_link_libraries(${PROJECT_NAME} EVEAuth curl OpenSSL::Crypto Threads::Threads dl wldap32 ws2_32)
```



