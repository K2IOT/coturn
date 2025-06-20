# JWT Library Integration for Coturn

This JWT library provides JSON Web Token functionality for the Coturn TURN server project.

## Features

- RS256 JWT token validation and generation
- Integrates with OpenSSL for cryptographic operations
- Optional support for libjwt, jansson, and libcjson libraries
- Compatible with Coturn's build system and coding standards

## Dependencies

### Required
- OpenSSL (for cryptographic operations)

### Optional
- `libjwt` - JWT library for C
- `jansson` - JSON library for C
- `libcjson` - Lightweight JSON library

## Usage in Code

```c
#include "jwt/jwt_integration.h"

// Initialize JWT subsystem
if (coturn_jwt_init() != 0) {
    // Handle initialization error
}

// Validate a JWT token
const char* token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...";
const char* public_key = "-----BEGIN PUBLIC KEY-----\n...";
if (coturn_jwt_validate_token(token, public_key) == 0) {
    // Token is valid
}

// Create a JWT token
char* new_token = coturn_jwt_create_token("username", "realm", 3600, private_key);
if (new_token) {
    // Use the token
    free(new_token);
}

// Cleanup
coturn_jwt_cleanup();
```

## Build Integration

The JWT library is automatically built as part of the Coturn project. It creates a static library `libturnjwt.a` that can be linked with other Coturn components.

### CMake Targets

- `turnjwt` - Static library target
- Available through namespace `coturn::turnjwt` when using find_package

### Preprocessor Definitions

The following macros are defined based on available dependencies:

- `HAVE_LIBJWT` - libjwt library is available
- `HAVE_JANSSON` - jansson library is available  
- `HAVE_CJSON` - libcjson library is available
- `TURN_NO_LIBJWT` - libjwt library is not available
- `TURN_NO_JANSSON` - jansson library is not available
- `TURN_NO_CJSON` - libcjson library is not available

## Installation

Headers are installed to: `${CMAKE_INSTALL_INCLUDEDIR}/turn/jwt/`
Library is installed to: `${CMAKE_INSTALL_LIBDIR}/`

## Integration Points

The JWT library is linked with:
- `turn_server` - Main server library
- `turnserver` - Main server executable

This allows JWT functionality to be used throughout the Coturn codebase for authentication and authorization purposes.
