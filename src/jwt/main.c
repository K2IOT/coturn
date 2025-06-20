#include <stdio.h>
#include <openssl/types.h>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>
#include "rs256.h"

EVP_PKEY* try_load_key_from_locations(const char* exe_dir) {
    char key_path[PATH_MAX];
    EVP_PKEY* public_key = NULL;

    // Try current directory first
    if (access("public_key.pem", F_OK) != -1) {
        public_key = load_public_key_from_file("public_key.pem");
        if (public_key) return public_key;
    }

    // Try executable directory
    snprintf(key_path, sizeof(key_path), "%s/public_key.pem", exe_dir);
    if (access(key_path, F_OK) != -1) {
        public_key = load_public_key_from_file(key_path);
        if (public_key) return public_key;
    }

    // Try project root directory
    snprintf(key_path, sizeof(key_path), "%s/../../public_key.pem", exe_dir);
    if (access(key_path, F_OK) != -1) {
        public_key = load_public_key_from_file(key_path);
        if (public_key) return public_key;
    }

    return NULL;
}

char* get_executable_dir() {
    static char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
    if (count != -1) {
        dirname(path);
        return path;
    }
    return NULL;
}

int main(void) {
    const char* accessToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2Nzc2MDU1MDNhYjdlYTdlZWJkYjk2ODMiLCJhcHBsaWNhdGlvblR5cGUiOiJNT0JJTEUiLCJwcm9qZWN0Um9sZXMiOlsiR1JPVVBfVVNFUiJdLCJwaG9uZSI6IjAxMjM0NTAwMDAiLCJzeXN0ZW1Sb2xlcyI6WyJTWVNURU1fVVNFUiJdLCJwcm9qZWN0VXNlcklkIjoiVklPVC0wMDMiLCJwcm9qZWN0SWQiOiI2NzBjNzEyY2VkNmFlNjc5OWMwZmJiN2YiLCJqdGkiOiI2ODUwZDZhMjVkNzU2ZjRkMTFlODFmNDYiLCJpYXQiOjE3NTAxMjgyOTAsImV4cCI6MTc1MDIxNDY5MH0.sk9YzrvdIIu9CGGuGUabsb97ht6XsHJgPBl671gwaUYiPVmCHvj9id93Cemno7ZR8Wrozp-IpRmz1n7mGdx434FF57QdGQpC3i9KyJN4vL2y3XIce_Ernx2sXlWOjW-672N-39u19Z4c_oyMKG2oUH0jdcEzPN25xJlUk46htIE4HZXE2fQqGmDsSmjBuiCNs9yY30mgf3I17G3vKZodazY9ESLe8R-0BdkfP5dOLVEBpDD93oxT8LaRFX4eOB4S8_EpLMbPwk_ugLtW1YTVNj3Zqr9-jGQL-Vcvs89GXBlazLIsFM1to_5FIs_Ngq9DCtcqj6SxfV42Ag-5Il5WLw";

    char* exe_dir = get_executable_dir();
    if (!exe_dir) {
        printf("❌ Failed to get executable directory\n");
        return 1;
    }

    EVP_PKEY* public_key = try_load_key_from_locations(exe_dir);
    if (!public_key) {
        printf("❌ Failed to load public_key.pem from any location\n");
        printf("💡 Make sure public_key.pem exists in the current directory or project root\n");
        return 1;
    }

    if (validate_token(accessToken, public_key)) {
        printf("✅ Token is VALID\n");
    } else {
        printf("❌ Token is INVALID\n");
    }
    return 0;
}
