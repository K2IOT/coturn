#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <jwt.h>
#include <time.h>
#include <errno.h>

// Load public key
EVP_PKEY* load_public_key_from_file(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("❌ Cannot open public key file: %s\n", filename);
        return NULL;
    }
    
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        printf("❌ Failed to load public key from file: %s\n", filename);
    } else {
        printf("✅ Successfully loaded public key from: %s\n", filename);
    }
    
    return pkey;
}

// Convert EVP_PKEY to PEM string
char* evp_pkey_to_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return NULL;
    }
    
    char* pem_data;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    
    char* pem_str = malloc(pem_len + 1);
    if (pem_str) {
        memcpy(pem_str, pem_data, pem_len);
        pem_str[pem_len] = '\0';
    }
    
    BIO_free(bio);
    return pem_str;
}

int main() {
    printf("=== Simple JWT Token Test ===\n");
    
    // Your JWT token  
    const char* your_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2NzIyMTExMDQzYzE5ZTdkNzhhZDUxYTEiLCJhcHBsaWNhdGlvblR5cGUiOiJNT0JJTEUiLCJwcm9qZWN0Um9sZXMiOlsiR1JPVVBfVVNFUiJdLCJwaG9uZSI6IjAwMSIsInN5c3RlbVJvbGVzIjpbIlNZU1RFTV9VU0VSIl0sInByb2plY3RVc2VySWQiOiI2NzIyMTExMDQzYzE5ZTdkNzhhZDUxYTAiLCJwcm9qZWN0SWQiOiI2NzBjNzEyY2VkNmFlNjc5OWMwZmJiN2YiLCJqdGkiOiI2ODU1MzRmNjMwOGMwMzRiYjI0YzYwYjIiLCJpYXQiOjE3NTA0MTQ1ODIsImV4cCI6MTc1MDQxNDY0Mn0.fr5Rx5Z2H_zRYSo6Byn5-R1mHaLmBAJHM8BlLhWLveAivdTHCjVy9pgrJQxbHanCKJrgPq9AYVCUnomSYNwOJPZjwrsHZaoqHqxTwGcbHJ6dv-Bx99hBBRET7Dt6TeySy7SWI6V1n0c4rHxPpXgZwXUoTm0GmJFdfgAnBjyXKlfEJeLcsrVpOoYyZoGjmPARdWPpudkL5rMDRdbJkyLHbjHOgU1_XN7iOHzFB7UrttrofW_xYKHJQAR_7LtcTQkwBB179eG7Ti9wd8-RhrpPplBgcHeLdP-1Vqp0CKdBR7LOulotIl_POlKWbsbqtAITuD317GuHItKJKHrT73R5LQ";
    
    printf("Token length: %zu bytes\n", strlen(your_token));
    
    // Check expiration first
    printf("\n=== Checking token expiration ===\n");
    // exp: 1750413848 = Wed Dec 20 2024 03:24:08 GMT+0000
    time_t exp_time = 1750413848;
    time_t now = time(NULL);
    printf("Token expires at: %ld (current time: %ld)\n", exp_time, now);
    if (exp_time < now) {
        printf("⚠️  WARNING: Token is EXPIRED!\n");
        printf("Token expired %ld seconds ago\n", now - exp_time);
    } else {
        printf("✅ Token is not expired (expires in %ld seconds)\n", exp_time - now);
    }
    
    // Try to load public keys from different locations
    printf("\n=== Loading public keys ===\n");
    
    const char* key_paths[] = {
        "src/jwt/public_key.pem",
        "src/jwt/public.pem", 
        "cmake-build-debug/bin/src/jwt/public_key.pem",
        "cmake-build-debug/bin/public_key.pem",
        NULL
    };
    
    EVP_PKEY* public_key = NULL;
    for (int i = 0; key_paths[i]; i++) {
        public_key = load_public_key_from_file(key_paths[i]);
        if (public_key) break;
    }
    
    if (!public_key) {
        printf("❌ Failed to load any public key\n");
        return 1;
    }
    
    // Convert to PEM string
    char* public_key_pem = evp_pkey_to_pem(public_key);
    if (!public_key_pem) {
        printf("❌ Failed to convert public key to PEM\n");
        EVP_PKEY_free(public_key);
        return 1;
    }
    
    printf("✅ Public key converted to PEM format\n");
    
    // Test JWT validation
    printf("\n=== JWT Validation Test ===\n");
    
    jwt_t* jwt = NULL;
    int decode_result = jwt_decode(&jwt, your_token, 
                                  (unsigned char*)public_key_pem, 
                                  strlen(public_key_pem));
    
    if (decode_result != 0) {
        printf("❌ JWT decode failed with error: %d\n", decode_result);
        if (decode_result == EINVAL) {
            printf("   Reason: Invalid JWT token format or signature\n");
        } else if (decode_result == ENOMEM) {
            printf("   Reason: Memory allocation error\n");
        } else {
            printf("   Reason: Unknown error\n");
        }
    } else {
        printf("✅ JWT decode successful!\n");
        
        // Get claims
        const char* sub = jwt_get_grant(jwt, "sub");
        const char* project_user_id = jwt_get_grant(jwt, "projectUserId");
        long iat = jwt_get_grant_int(jwt, "iat");
        long exp = jwt_get_grant_int(jwt, "exp");
        
        printf("   Subject: %s\n", sub ? sub : "N/A");
        printf("   Project User ID: %s\n", project_user_id ? project_user_id : "N/A");
        printf("   Issued at: %ld\n", iat);
        printf("   Expires at: %ld\n", exp);
        
        jwt_free(jwt);
    }
    
    // Cleanup
    free(public_key_pem);
    EVP_PKEY_free(public_key);
    
    printf("\n=== Test completed ===\n");
    return 0;
} 