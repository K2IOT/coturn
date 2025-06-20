/*
 * rs256.h - JWT RS256 Utility Library Header
 */

#ifndef RS256_H
#define RS256_H

#include <time.h>
#include <openssl/evp.h>

// Constants
#define JWT_SUCCESS 1
#define JWT_FAILURE 0

// Authentication claim constants
typedef struct {
    const char* JTI;
} authentication_claim_t;

extern const authentication_claim_t Authentication_Claim;

// Function declarations

// Core JWT functions
char* generate_token(const char* subject, 
                    const char* custom_claims_json, 
                    long expiration_ms, 
                    EVP_PKEY* private_key);

int validate_token(const char* token, EVP_PKEY* public_key);

char* get_subject_from_token(const char* token, EVP_PKEY* public_key);

time_t get_expiration_date_from_token(const char* token, EVP_PKEY* public_key);

char* get_claim_from_token(const char* token, 
                          const char* claim_name, 
                          EVP_PKEY* public_key);

int is_token_expired(const char* token, EVP_PKEY* public_key);

char* get_all_claims_from_token(const char* token, EVP_PKEY* public_key);

// Utility functions
EVP_PKEY* load_private_key_from_file(const char* filename);
EVP_PKEY* load_public_key_from_file(const char* filename);
const char* get_last_error(void);

// Helper functions
int has_text(const char* str);
char* evp_pkey_to_pem(EVP_PKEY* pkey, int is_private);
void log_error(const char* format, ...);

#endif // RS256_H