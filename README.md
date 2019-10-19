# libEVEAuth
## Still in progress... not working yet
libEVEAuth will be a simple library for authentication handling with the 
[EVE swagger interface](https://github.com/esi/esi-docs) 'ESI' for a native C++ application.

If you want to make a native C++ application... this library is for you.\
If you want to make a native C application... this library is **not** for you.

Target for now is only Linux.

#### First Milestone - in progress:
The first milestone will be the implementation of the 
[standard authentication](https://github.com/esi/esi-docs/blob/master/docs/sso/native_sso_flow.md) 
for native applications as shown in the [python example](https://github.com/esi/esi-docs/tree/master/examples/python/sso). 
Therefore, after reaching this milestone you will be able to access
data which need an access token (authentication) with this library.

#### Second Milestone:
The next step is then to implement the handling of the refresh token and targeting windows too.

#### Dependencies:
For now:
- OpenSSL
- libcurl
