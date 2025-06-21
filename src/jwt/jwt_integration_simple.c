/*
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * JWT Integration Implementation for Coturn - Complete Version
 */

#include "jwt_integration.h"
#include "rs256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Include STUN API for parsing
#include "../client/ns_turn_msg.h"

// Custom STUN attributes
#define STUN_ATTRIBUTE_JWT_TOKEN (0x8040)
#define STUN_MAX_JWT_TOKEN_SIZE (800)
#define STUN_HEADER_LENGTH (20)

// Global variables for JWT context
static int jwt_initialized = 0;

/*
 * Initialize JWT subsystem
 */
int coturn_jwt_init(void) {
    if (jwt_initialized) {
        return 0;
    }
    
    jwt_initialized = 1;
    printf("JWT: Subsystem initialized\n");
    return 0;
}

/*
 * Cleanup JWT subsystem
 */
void coturn_jwt_cleanup(void) {
    jwt_initialized = 0;
    printf("JWT: Subsystem cleaned up\n");
}

/*
 * Load public key from file with fallback locations
 */
static EVP_PKEY* load_public_key_with_fallback(const char* filename) {
    EVP_PKEY* key = NULL;
    char full_path[1024];
    
    // Try locations in order of preference
    const char* locations[] = {
        "src/jwt/",                     // Relative to project root
        "./jwt/",                       // Relative jwt directory
        "./",                           // Current directory
        "/etc/coturn/jwt/",            // System directory
        "/usr/local/etc/coturn/jwt/",  // Alternative system directory
        NULL
    };
    
    for (int i = 0; locations[i]; i++) {
        snprintf(full_path, sizeof(full_path), "%s%s", locations[i], filename);
        
        // Check if file exists and is readable
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            key = load_public_key_from_file(full_path);
            if (key) {
                printf("JWT: Successfully loaded public key from %s\n", full_path);
                break;
            } else {
                printf("JWT: Failed to parse public key from %s\n", full_path);
            }
        }
    }
    
    if (!key) {
        printf("JWT: Public key file '%s' not found in any of the search locations\n", filename);
    }
    
    return key;
}

/*
 * Validate JWT token using public key file
 */
int coturn_jwt_validate_token(const char* token, const char* public_key_file) {
    if (!jwt_initialized) {
        if (coturn_jwt_init() != 0) {
            return 0;
        }
    }
    
    if (!token || !public_key_file) {
        printf("JWT: Token and public key file required\n");
        return 0;
    }
    
    // Load public key
    EVP_PKEY* public_key = load_public_key_with_fallback(public_key_file);
    if (!public_key) {
        printf("JWT: Failed to load public key from %s\n", public_key_file);
        return 0;
    }
    
    int result = validate_token(token, public_key);
    EVP_PKEY_free(public_key);
    
    if (result) {
        printf("JWT: Token validation successful\n");
    } else {
        printf("JWT: Token validation failed\n");
    }
    
    return result;
}

/*
 * Create JWT token using private key file
 */
char* coturn_jwt_create_token(const char* username, const char* realm, int ttl, const char* private_key_file) {
    if (!jwt_initialized) {
        if (coturn_jwt_init() != 0) {
            return NULL;
        }
    }
    
    if (!username || !realm || !private_key_file) {
        printf("JWT: Username, realm and private key file required\n");
        return NULL;
    }
    
    // Load private key
    EVP_PKEY* private_key = load_private_key_from_file(private_key_file);
    if (!private_key) {
        printf("JWT: Failed to load private key from %s\n", private_key_file);
        return NULL;
    }
    
    // Create custom claims JSON
    char claims_json[512];
    snprintf(claims_json, sizeof(claims_json),
        "{"
        "\"username\":\"%s\","
        "\"realm\":\"%s\","
        "\"iss\":\"coturn-server\","
        "\"aud\":\"coturn-client\""
        "}", username, realm);
    
    // Generate token with TTL in milliseconds
    char* token = generate_token(username, claims_json, (long)ttl * 1000, private_key);
    EVP_PKEY_free(private_key);
    
    if (token) {
        printf("JWT: Token created successfully for user %s\n", username);
    } else {
        printf("JWT: Failed to create token for user %s\n", username);
    }
    
    return token;
}

/*
 * Extract username from JWT token
 */
char* coturn_jwt_get_username(const char* token, const char* public_key_file) {
    if (!jwt_initialized) {
        if (coturn_jwt_init() != 0) {
            return NULL;
        }
    }
    
    EVP_PKEY* public_key = load_public_key_with_fallback(public_key_file);
    if (!public_key) {
        return NULL;
    }
    
    char* username = get_claim_from_token(token, "username", public_key);
    if (!username) {
        // Fallback to subject
        username = get_subject_from_token(token, public_key);
    }
    
    EVP_PKEY_free(public_key);
    
    if (username) {
        printf("JWT: Extracted username: %s\n", username);
    }
    
    return username;
}

/*
 * Extract realm from JWT token (deprecated - use STUN protocol realm instead)
 * This function is kept for backward compatibility but should not be used.
 * JWT tokens should only be used for authentication validation.
 */
char* coturn_jwt_get_realm(const char* token, const char* public_key_file) {
    if (!jwt_initialized) {
        if (coturn_jwt_init() != 0) {
            return NULL;
        }
    }
    
    EVP_PKEY* public_key = load_public_key_with_fallback(public_key_file);
    if (!public_key) {
        return NULL;
    }
    
    char* realm = get_claim_from_token(token, "realm", public_key);
    EVP_PKEY_free(public_key);
    
    if (realm) {
        printf("JWT: Extracted realm: %s (deprecated - use STUN realm instead)\n", realm);
        return realm;
    } else {
        printf("JWT: No realm in token (this is expected - use STUN realm instead)\n");
        return NULL;
    }
}

/*
 * Add JWT token to STUN message as custom attribute
 */
int add_jwt_token_to_stun_msg(uint8_t* buf, size_t* len, const char* jwt_token) {
    if (!buf || !len || !jwt_token) {
        printf("JWT: Invalid parameters for adding token to STUN message\n");
        return -1;
    }
    
    size_t token_len = strlen(jwt_token);
    if (token_len > STUN_MAX_JWT_TOKEN_SIZE) {
        printf("JWT: Token too large (%zu bytes, max %d)\n", token_len, STUN_MAX_JWT_TOKEN_SIZE);
        return -1;
    }
    
    // Add JWT token as custom STUN attribute using correct API
    if (!stun_attr_add_str(buf, len, STUN_ATTRIBUTE_JWT_TOKEN, 
                          (const uint8_t*)jwt_token, (int)token_len)) {
        printf("JWT: Failed to add token to STUN message\n");
        return -1;
    }
    
    printf("JWT: Successfully added token to STUN message (length: %zu)\n", token_len);
    return 0;
}

/*
 * Extract JWT token from STUN message buffer using direct STUN parsing
 */
char* extract_jwt_token_from_stun_msg(const uint8_t* buf, size_t len) {
    if (!buf || len < STUN_HEADER_LENGTH) {
        printf("JWT: Invalid STUN message buffer\n");
        return NULL;
    }
    
    // Use direct STUN attribute parsing
    stun_attr_ref sar = stun_attr_get_first_str(buf, len);
    while (sar) {
        int attr_type = stun_attr_get_type(sar);
        
        if (attr_type == STUN_ATTRIBUTE_JWT_TOKEN) {
            int attr_len = stun_attr_get_len(sar);
            if (attr_len <= 0 || attr_len > STUN_MAX_JWT_TOKEN_SIZE) {
                printf("JWT: Invalid token length in STUN message: %d\n", attr_len);
                return NULL;
            }
            
            const uint8_t* attr_value = stun_attr_get_value(sar);
            if (!attr_value) {
                printf("JWT: Failed to get attribute value\n");
                return NULL;
            }
            
            // Allocate and copy JWT token string (null-terminated)
            char* jwt_token = (char*)malloc(attr_len + 1);
            if (!jwt_token) {
                printf("JWT: Memory allocation failed for token\n");
                return NULL;
            }
            
            memcpy(jwt_token, attr_value, attr_len);
            jwt_token[attr_len] = '\0';
            
            printf("JWT: Successfully extracted token from STUN message (length: %d)\n", attr_len);
            return jwt_token;
        }
        
        // Move to next attribute
        sar = stun_attr_get_next_str(buf, len, sar);
    }
    
    printf("JWT: No JWT token found in STUN message\n");
    return NULL;
}

/*
 * Extract JWT token from parsed STUN message structure (when available)
 */
char* extract_jwt_token_from_parsed_msg(ns_turn_msg* msg) {
    if (!msg) {
        printf("JWT: Invalid message structure\n");
        return NULL;
    }
    
    // This function is for future compatibility when msg structure is available
    // For now, return NULL to indicate not implemented for parsed messages
    printf("JWT: Parsed message extraction not yet implemented\n");
    return NULL;
} 