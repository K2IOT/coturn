/*
 * rs256.c - JWT RS256 Utility Library in C
 * 
 * Converted from Java JwtRS256Util class
 * Dependencies:
 * - OpenSSL (libssl-dev)
 * - cJSON (libcjson-dev) 
 * - libjwt (libjwt-dev)
 * 
 * Compile: gcc -o rs256 rs256.c -ljwt -lssl -lcrypto -lcjson
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

// JWT library
#include <jwt.h>

// OpenSSL libraries
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// JSON library
#include <cjson/cJSON.h>

// Constants
#define MAX_TOKEN_SIZE 4096
#define MAX_CLAIM_SIZE 512
#define MAX_ERROR_MSG 256
#define JWT_SUCCESS 1
#define JWT_FAILURE 0

// Error handling
static char last_error[MAX_ERROR_MSG] = {0};

// Logging function (equivalent to Java's log.error)
void log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    
    // Store last error for debugging
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
}

// Get last error message
const char* get_last_error() {
    return last_error;
}

// Helper function to convert EVP_PKEY to PEM string
char* evp_pkey_to_pem(EVP_PKEY* pkey, int is_private) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        log_error("Failed to create BIO");
        return NULL;
    }
    
    int result;
    if (is_private) {
        result = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    } else {
        result = PEM_write_bio_PUBKEY(bio, pkey);
    }
    
    if (!result) {
        log_error("Failed to write key to BIO");
        BIO_free(bio);
        return NULL;
    }
    
    char* pem_data;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    
    char* pem_str = malloc(pem_len + 1);
    if (!pem_str) {
        log_error("Memory allocation failed");
        BIO_free(bio);
        return NULL;
    }
    
    memcpy(pem_str, pem_data, pem_len);
    pem_str[pem_len] = '\0';
    
    BIO_free(bio);
    return pem_str;
}

// Check if string has text (equivalent to StringUtils.hasText)
int has_text(const char* str) {
    return str != NULL && strlen(str) > 0;
}

/*
 * Generate JWT token with RS256 signature
 * 
 * @param subject: Token subject (can be NULL)
 * @param custom_claims_json: JSON string with custom claims (can be NULL)
 * @param expiration_ms: Token expiration in milliseconds from now
 * @param private_key: RSA private key for signing
 * @return: JWT token string (caller must free) or NULL on error
 */
char* generate_token(const char* subject, 
                    const char* custom_claims_json, 
                    long expiration_ms, 
                    EVP_PKEY* private_key) {
    
    if (!private_key) {
        log_error("Private key is required");
        return NULL;
    }
    
    jwt_t* jwt = NULL;
    char* token = NULL;
    char* private_key_pem = NULL;
    cJSON* custom_claims = NULL;
    
    // Create new JWT
    if (jwt_new(&jwt) != 0) {
        log_error("Failed to create JWT object");
        return NULL;
    }
    
    // Set algorithm to RS256
    private_key_pem = evp_pkey_to_pem(private_key, 1);
    if (!private_key_pem) {
        log_error("Failed to convert private key to PEM");
        goto cleanup;
    }
    
    if (jwt_set_alg(jwt, JWT_ALG_RS256, 
                    (unsigned char*)private_key_pem, 
                    strlen(private_key_pem)) != 0) {
        log_error("Failed to set JWT algorithm");
        goto cleanup;
    }
    
    // Set subject if provided
    if (has_text(subject)) {
        if (jwt_add_grant(jwt, "sub", subject) != 0) {
            log_error("Failed to add subject claim");
            goto cleanup;
        }
    }
    
    // Add custom claims if provided
    if (has_text(custom_claims_json)) {
        custom_claims = cJSON_Parse(custom_claims_json);
        if (custom_claims && cJSON_IsObject(custom_claims)) {
            cJSON* claim = NULL;
            cJSON_ArrayForEach(claim, custom_claims) {
                if (cJSON_IsString(claim)) {
                    jwt_add_grant(jwt, claim->string, claim->valuestring);
                } else if (cJSON_IsNumber(claim)) {
                    jwt_add_grant_int(jwt, claim->string, claim->valueint);
                } else if (cJSON_IsBool(claim)) {
                    jwt_add_grant_bool(jwt, claim->string, cJSON_IsTrue(claim));
                }
            }
        } else {
            log_error("Invalid custom claims JSON");
        }
    }
    
    // Set issued at time
    time_t now = time(NULL);
    if (jwt_add_grant_int(jwt, "iat", now) != 0) {
        log_error("Failed to add issued at claim");
        goto cleanup;
    }
    
    // Set expiration time
    time_t exp = now + (expiration_ms / 1000);
    if (jwt_add_grant_int(jwt, "exp", exp) != 0) {
        log_error("Failed to add expiration claim");
        goto cleanup;
    }
    
    // Encode token
    token = jwt_encode_str(jwt);
    if (!token) {
        log_error("Failed to encode JWT token");
        goto cleanup;
    }
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (private_key_pem) free(private_key_pem);
    if (custom_claims) cJSON_Delete(custom_claims);
    
    return token;
}

/*
 * Validate JWT token signature and expiration
 * 
 * @param token: JWT token string
 * @param public_key: RSA public key for verification
 * @return: JWT_SUCCESS (1) if valid, JWT_FAILURE (0) if invalid
 */
int validate_token(const char* token, EVP_PKEY* public_key) {
    if (!token || !public_key) {
        log_error("Token and public key are required");
        return JWT_FAILURE;
    }
    
    jwt_t* jwt = NULL;
    char* public_key_pem = NULL;
    int result = JWT_FAILURE;
    
    public_key_pem = evp_pkey_to_pem(public_key, 0);
    if (!public_key_pem) {
        log_error("Failed to convert public key to PEM");
        return JWT_FAILURE;
    }
    
    // Decode and verify token
    int decode_result = jwt_decode(&jwt, token, 
                                  (unsigned char*)public_key_pem, 
                                  strlen(public_key_pem));
    
    if (decode_result != 0) {
        // Check specific error types
        if (decode_result == EINVAL) {
            log_error("Invalid JWT token format");
        } else {
            log_error("JWT token verification failed");
        }
        goto cleanup;
    }
    
    // Check expiration
    time_t now = time(NULL);
    long exp = jwt_get_grant_int(jwt, "exp");
    
    if (exp <= 0) {
        log_error("JWT token missing expiration claim");
        goto cleanup;
    }
    
    if (exp < now) {
        log_error("JWT token is expired");
        goto cleanup;
    }
    
    result = JWT_SUCCESS;
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (public_key_pem) free(public_key_pem);
    
    return result;
}

/*
 * Get subject from JWT token
 * 
 * @param token: JWT token string
 * @param public_key: RSA public key for verification
 * @return: Subject string (caller must free) or NULL on error
 */
char* get_subject_from_token(const char* token, EVP_PKEY* public_key) {
    if (!token || !public_key) {
        log_error("Token and public key are required");
        return NULL;
    }
    
    jwt_t* jwt = NULL;
    char* public_key_pem = NULL;
    char* subject = NULL;
    
    public_key_pem = evp_pkey_to_pem(public_key, 0);
    if (!public_key_pem) {
        log_error("Failed to convert public key to PEM");
        return NULL;
    }
    
    if (jwt_decode(&jwt, token, 
                   (unsigned char*)public_key_pem, 
                   strlen(public_key_pem)) != 0) {
        log_error("Failed to decode JWT token");
        goto cleanup;
    }
    
    const char* sub = jwt_get_grant(jwt, "sub");
    if (sub) {
        subject = strdup(sub);
        if (!subject) {
            log_error("Memory allocation failed");
        }
    }
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (public_key_pem) free(public_key_pem);
    
    return subject;
}

/*
 * Get expiration date from JWT token
 * 
 * @param token: JWT token string
 * @param public_key: RSA public key for verification
 * @return: Expiration timestamp or 0 on error
 */
time_t get_expiration_date_from_token(const char* token, EVP_PKEY* public_key) {
    if (!token || !public_key) {
        log_error("Token and public key are required");
        return 0;
    }
    
    jwt_t* jwt = NULL;
    char* public_key_pem = NULL;
    time_t exp = 0;
    
    public_key_pem = evp_pkey_to_pem(public_key, 0);
    if (!public_key_pem) {
        log_error("Failed to convert public key to PEM");
        return 0;
    }
    
    if (jwt_decode(&jwt, token, 
                   (unsigned char*)public_key_pem, 
                   strlen(public_key_pem)) != 0) {
        log_error("Failed to decode JWT token");
        goto cleanup;
    }
    
    exp = jwt_get_grant_int(jwt, "exp");
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (public_key_pem) free(public_key_pem);
    
    return exp;
}

/*
 * Check if JWT token is expired
 * 
 * @param token: JWT token string
 * @param public_key: RSA public key for verification
 * @return: 1 if expired, 0 if not expired or error
 */
int is_token_expired(const char* token, EVP_PKEY* public_key) {
    time_t exp = get_expiration_date_from_token(token, public_key);
    if (exp == 0) {
        return 1; // Consider invalid token as expired
    }
    
    time_t now = time(NULL);
    return exp < now;
}

/*
 * Get all claims from JWT token as JSON string
 * 
 * @param token: JWT token string
 * @param public_key: RSA public key for verification
 * @return: JSON string with all claims (caller must free) or NULL on error
 */
char* get_all_claims_from_token(const char* token, EVP_PKEY* public_key) {
    if (!token || !public_key) {
        log_error("Token and public key are required");
        return NULL;
    }
    
    jwt_t* jwt = NULL;
    char* public_key_pem = NULL;
    char* claims_json = NULL;
    
    public_key_pem = evp_pkey_to_pem(public_key, 0);
    if (!public_key_pem) {
        log_error("Failed to convert public key to PEM");
        return NULL;
    }
    
    if (jwt_decode(&jwt, token, 
                   (unsigned char*)public_key_pem, 
                   strlen(public_key_pem)) != 0) {
        log_error("Failed to decode JWT token");
        goto cleanup;
    }
    
    // Get claims as JSON string
    claims_json = jwt_dump_str(jwt, 1); // 1 for pretty print
    if (!claims_json) {
        log_error("Failed to dump JWT claims");
    }
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (public_key_pem) free(public_key_pem);
    
    return claims_json;
}

/*
 * Get specific claim from JWT token
 * 
 * @param token: JWT token string
 * @param claim_name: Name of the claim to retrieve
 * @param public_key: RSA public key for verification
 * @return: Claim value string (caller must free) or NULL on error
 */
char* get_claim_from_token(const char* token, 
                          const char* claim_name, 
                          EVP_PKEY* public_key) {
    if (!token || !claim_name || !public_key) {
        log_error("Token, claim name, and public key are required");
        return NULL;
    }
    
    jwt_t* jwt = NULL;
    char* public_key_pem = NULL;
    char* claim_value = NULL;
    
    public_key_pem = evp_pkey_to_pem(public_key, 0);
    if (!public_key_pem) {
        log_error("Failed to convert public key to PEM");
        return NULL;
    }
    
    if (jwt_decode(&jwt, token, 
                   (unsigned char*)public_key_pem, 
                   strlen(public_key_pem)) != 0) {
        log_error("Failed to decode JWT token");
        goto cleanup;
    }
    
    const char* claim = jwt_get_grant(jwt, claim_name);
    if (claim) {
        claim_value = strdup(claim);
        if (!claim_value) {
            log_error("Memory allocation failed");
        }
    }
    
cleanup:
    if (jwt) jwt_free(jwt);
    if (public_key_pem) free(public_key_pem);
    
    return claim_value;
}

// Authentication claim constants (equivalent to Java nested class)
typedef struct {
    const char* JTI;
} authentication_claim_t;

static const authentication_claim_t Authentication_Claim = {
    .JTI = "jti"
};

/*
 * Load RSA private key from PEM file
 */
EVP_PKEY* load_private_key_from_file(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        log_error("Cannot open private key file: %s", filename);
        return NULL;
    }
    
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        log_error("Failed to load private key from file: %s", filename);
    }
    
    return pkey;
}

/*
 * Load RSA public key from PEM file
 */
EVP_PKEY* load_public_key_from_file(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        log_error("Cannot open public key file: %s", filename);
        return NULL;
    }
    
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        log_error("Failed to load public key from file: %s", filename);
    }
    
    return pkey;
}

/*
 * Generate RSA key pair for testing
 */
void generate_test_keys() {
    // Generate private key
    system("openssl genrsa -out private_key.pem 2048");
    // Extract public key
    system("openssl rsa -in private_key.pem -pubout -out public_key.pem");
}
