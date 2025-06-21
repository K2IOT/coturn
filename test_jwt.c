#include "src/jwt/jwt_integration.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize JWT system
    if (coturn_jwt_init() != 0) {
        printf("Failed to initialize JWT system\n");
        return 1;
    }
    
    printf("JWT system initialized successfully\n");
    
    // Create a test JWT token
    char *test_token = coturn_jwt_create_token("testuser", "testrealm", 3600, "src/jwt/private_key.pem");
    if (test_token) {
        printf("Generated JWT token: %s\n", test_token);
        
        // Validate the token
        int valid = coturn_jwt_validate_token(test_token, "src/jwt/public_key.pem");
        printf("Token validation result: %s\n", valid ? "VALID" : "INVALID");
        
        if (valid) {
            // Extract username
            char *username = coturn_jwt_get_username(test_token, "src/jwt/public_key.pem");
            if (username) {
                printf("Extracted username: %s\n", username);
                free(username);
            }
            
            // Extract realm
            char *realm = coturn_jwt_get_realm(test_token, "src/jwt/public_key.pem");
            if (realm) {
                printf("Extracted realm: %s\n", realm);
                free(realm);
            }
        }
        
        free(test_token);
    } else {
        printf("Failed to create JWT token\n");
    }
    
    // Cleanup
    coturn_jwt_cleanup();
    
    return 0;
} 