# libEVEAuth
## Still in progress... not working yet
libEVEAuth is a simple library for authentication handling with the 
[EVE swagger interface](https://github.com/esi/esi-docs) 'ESI' for a native C++ application.

If you want to make a native C++ application... this library is for you.\
If you want to make a native C application... this library is **not** for you.

Target for now is Linux.

#### First Milestone - reached:
The first milestone will be the implementation of the 
[standard authentication](https://github.com/esi/esi-docs/blob/master/docs/sso/native_sso_flow.md) 
for native applications as shown in the [python example](https://github.com/esi/esi-docs/tree/master/examples/python/sso). 
Therefore, after reaching this milestone you will be able to access
data which need an access token (authentication) with this library.

This milestone is reached. You can now access your data which need authentication with this library. 

#### ~~Second Milestone:~~
~~The next step is then to implement the handling of the refresh token and targeting windows too.~~

#### Second Milestone - in progress:
Cleaning up the code. Write a introduction for building and usage. 

#### Third Milestone - outstanding:
Handle token refreshing.

#### Fourth Milestone - outstanding:
Checking for proper third party library insertion.

#### Fifth Milestone - outstanding:
Checking for windows support.

#### Dependencies:
- [OpenSSL](https://www.openssl.org/)
- [libcurl](https://curl.haxx.se/libcurl/)

#### Third party libraries used:
- [picojson](https://github.com/kazuho/picojson) by Kazuho
- [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) by Thalhammer

