/*
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * JWT Integration Header for Coturn
 */

#ifndef JWT_INTEGRATION_H
#define JWT_INTEGRATION_H

#include <stdint.h>
#include <stddef.h>

// Forward declaration for STUN message structure
typedef struct ns_turn_msg ns_turn_msg;

// Custom STUN attributes
#define STUN_ATTRIBUTE_JWT_TOKEN (0x8040)
#define STUN_MAX_JWT_TOKEN_SIZE (800)

// JWT subsystem initialization
int coturn_jwt_init(void);
void coturn_jwt_cleanup(void);

// JWT token operations
int coturn_jwt_validate_token(const char* token, const char* public_key_file);
char* coturn_jwt_create_token(const char* username, const char* realm, int ttl, const char* private_key_file);
char* coturn_jwt_get_username(const char* token, const char* public_key_file);
char* coturn_jwt_get_realm(const char* token, const char* public_key_file); // DEPRECATED: Use STUN realm instead

// STUN message integration
int add_jwt_token_to_stun_msg(uint8_t* buf, size_t* len, const char* jwt_token);
char* extract_jwt_token_from_stun_msg(const uint8_t* buf, size_t len);
char* extract_jwt_token_from_parsed_msg(ns_turn_msg* msg);

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

#endif /* JWT_INTEGRATION_H */ 