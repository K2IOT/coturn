#ifndef JWT_INTEGRATION_H
#define JWT_INTEGRATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "rs256.h"

// JWT integration functions for Coturn
int coturn_jwt_init(void);
int coturn_jwt_validate_token(const char* token, const char* public_key);
char* coturn_jwt_create_token(const char* username, const char* realm, int ttl, const char* private_key);
void coturn_jwt_cleanup(void);

// Configuration macros
#ifdef HAVE_LIBJWT
    #define JWT_ENABLED 1
#else
    #define JWT_ENABLED 0
#endif

#ifdef HAVE_JANSSON
    #define JSON_JANSSON_ENABLED 1
#else
    #define JSON_JANSSON_ENABLED 0
#endif

#ifdef HAVE_CJSON
    #define JSON_CJSON_ENABLED 1
#else
    #define JSON_CJSON_ENABLED 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* JWT_INTEGRATION_H */ 