# JWT Integration for Coturn TURN Server

This directory contains the JWT (JSON Web Token) integration implementation for the Coturn TURN server, providing authentication via JWT tokens transmitted through custom STUN attributes.

## Overview

The JWT integration allows clients to authenticate using JWT tokens instead of traditional username/password authentication. The JWT token is transmitted via a custom STUN attribute (0x8040) with support for tokens up to 400 bytes.

## Features

- **JWT Token Validation**: RS256 signature validation using public key files
- **Custom STUN Attribute**: JWT tokens transmitted via STUN attribute 0x8040
- **Multiple Key Support**: Automatic fallback across multiple public key files
- **Username/Realm Extraction**: Automatic extraction of username and realm from JWT claims
- **Client Integration**: New `-A` flag in `turnutils_uclient` for JWT token input
- **Server Integration**: Automatic JWT validation in ALLOCATE requests

## Configuration Guide for turnserver.conf

### Basic JWT Configuration

To enable JWT authentication in your Coturn TURN server, you need to configure the `turnserver.conf` file with the following JWT-specific options:

#### 1. Enable JWT Authentication Mode

Add the following to your `turnserver.conf`:

```bash
# Enable JWT authentication mode
# This replaces traditional username/password authentication
jwt=1

# Specify the public key file for JWT token validation
# This is the path to the RSA public key file used to verify JWT signatures
jwt-public-key=/etc/coturn/jwt/public_key.pem
```

#### 2. Complete JWT Configuration Example

Here's a complete `turnserver.conf` configuration for JWT mode:

```bash
# Basic TURN server configuration
listening-port=3478
tls-listening-port=5349
listening-ip=0.0.0.0
relay-ip=0.0.0.0

# JWT Authentication Configuration
# ================================

# Enable JWT authentication mode (REQUIRED)
# When enabled, the server will only accept JWT tokens for authentication
# Traditional username/password authentication will be disabled
jwt=1

# JWT Public Key File (REQUIRED when jwt=1)
# Path to the RSA public key file used to verify JWT token signatures
# The server will use this key to validate incoming JWT tokens
jwt-public-key=/etc/coturn/jwt/public_key.pem

# Realm configuration (REQUIRED)
# The realm is still required for TURN functionality
# JWT tokens should NOT include realm - use STUN protocol realm instead
realm=mycompany.org

# Port range for relay endpoints
min-port=10000
max-port=65535

# Logging configuration
verbose
log-file=/var/log/turnserver/turnserver.log

# TLS/DTLS certificates (if using secure connections)
cert=/etc/coturn/cert.pem
pkey=/etc/coturn/privkey.pem

# Additional security options
fingerprint
# Note: lt-cred-mech is automatically disabled when jwt=1
# Note: no-auth is automatically disabled when jwt=1
```

#### 3. JWT Key File Locations

The JWT integration automatically searches for public key files in the following order:

1. **Configured Path**: The exact path specified in `jwt-public-key` option
2. **Fallback Locations** (if configured path fails):
   - `src/jwt/` (relative to project root)
   - `./jwt/` (relative jwt directory)
   - `./` (current directory)
   - `/etc/coturn/jwt/` (system directory)
   - `/usr/local/etc/coturn/jwt/` (alternative system directory)

The system will try these filenames in order:
- `public_key.pem`
- `public.pem`
- `rsa_public.pem`
- `jwt_public.pem`

#### 4. Command Line Equivalent

You can also start the server with command-line options instead of using the config file:

```bash
# Start turnserver with JWT authentication
./turnserver \
  --jwt=1 \
  --jwt-public-key=/etc/coturn/jwt/public_key.pem \
  --realm=mycompany.org \
  --listening-port=3478 \
  --tls-listening-port=5349 \
  --min-port=10000 \
  --max-port=65535 \
  --verbose \
  --log-file=stdout
```

#### 5. Security Considerations for Configuration

```bash
# JWT-specific security settings in turnserver.conf

# Enable JWT mode
jwt=1
jwt-public-key=/etc/coturn/jwt/public_key.pem

# Important: These options are INCOMPATIBLE with JWT mode
# Do NOT use these when jwt=1 is enabled:
# lt-cred-mech          # Conflicts with JWT authentication
# no-auth               # Conflicts with JWT authentication  
# use-auth-secret       # Use JWT instead of shared secrets
# static-auth-secret    # Not needed with JWT

# Recommended security options for JWT mode
realm=secure.company.com
fingerprint                    # Enable STUN message fingerprints
secure-stun                   # Require authentication for STUN requests
check-origin-consistency      # Verify origin consistency across session
no-multicast-peers           # Security: disable multicast peers
# allow-loopback-peers         # Only enable for testing!

# TLS/DTLS security (recommended for production)
cert=/etc/coturn/cert.pem
pkey=/etc/coturn/privkey.pem
cipher-list=ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
no-tlsv1                     # Disable TLS 1.0
no-tlsv1_1                   # Disable TLS 1.1 (optional)

# Logging for security monitoring
log-file=/var/log/turnserver/turnserver.log
syslog                       # Also log to syslog
verbose                      # Enable detailed logging for JWT operations
```

### JWT vs Traditional Authentication Configuration

| Authentication Mode | Configuration Required | Notes |
|-------------------|----------------------|--------|
| **JWT Mode** | `jwt=1`<br>`jwt-public-key=<path>` | Replaces username/password auth |
| **Long-term Credentials** | `lt-cred-mech`<br>`userdb=<path>` | Traditional database-based auth |
| **Short-term Credentials** | `use-auth-secret`<br>`static-auth-secret=<secret>` | REST API with shared secrets |
| **No Authentication** | `no-auth` | Anonymous access (not recommended) |

**Important**: Only ONE authentication mode can be active at a time. JWT mode automatically disables other authentication mechanisms.

### Deployment Checklist

Before deploying JWT authentication in production:

- [ ] Generate secure RSA key pair (minimum 2048 bits)
- [ ] Place public key in secure location with proper permissions
- [ ] Test JWT token validation with sample tokens
- [ ] Configure proper realm for your domain
- [ ] Enable TLS/DTLS for secure transport
- [ ] Set up proper logging and monitoring
- [ ] Test client applications with JWT authentication
- [ ] Document JWT token format and claims for developers
- [ ] Set up key rotation procedures

### Troubleshooting JWT Configuration

Common configuration issues:

1. **"JWT Token Required" errors**:
   - Ensure `jwt=1` is set in config
   - Verify client is sending JWT tokens in STUN attribute 0x8040

2. **"Invalid JWT Token" errors**:
   - Check `jwt-public-key` path is correct
   - Verify public key file permissions (readable by turnserver)
   - Ensure JWT token is properly signed with corresponding private key

3. **"Token validation failed" errors**:
   - Verify JWT token format and claims
   - Check token expiration time
   - Ensure public/private key pair match

4. **Server startup errors**:
   - Verify public key file exists and is readable
   - Check file format (must be PEM format)
   - Ensure no conflicting authentication options are set

## Files

### Core Implementation
- `jwt_integration_simple.c` - Complete JWT integration implementation
- `jwt_integration.h` - Header file with function declarations
- `rs256.c/rs256.h` - RS256 signature validation implementation
- `main.c` - Example JWT token generation utility

### Key Management
- `generate_sample_keys.sh` - RSA key pair generation script

## Public Key Search Locations

The JWT validation will search for public key files in the following order:

1. `src/jwt/` (relative to project root)
2. `./jwt/` (relative jwt directory)
3. `./` (current directory)
4. `/etc/coturn/jwt/` (system directory)
5. `/usr/local/etc/coturn/jwt/` (alternative system directory)

## Public Key File Names

The system will try these filenames in order:
- `public.pem`
- `rsa_public.pem`
- `jwt_public.pem`
- `public_key.pem`

## Usage

### 1. Key Generation

Generate RSA key pairs for JWT signing:

```bash
cd src/jwt
./generate_sample_keys.sh
```

This creates:
- `private_key.pem` - Private key for token signing
- `public.pem` - Public key for token validation

### 2. JWT Token Format

Tokens should include these claims:
- `username`: User identifier
- `realm`: Authentication realm
- `iss`: Issuer (typically "coturn-server")
- `aud`: Audience (typically "coturn-client")

Example JWT payload:
```json
{
  "username": "testuser",
  "realm": "testrealm",
  "iss": "coturn-server",
  "aud": "coturn-client",
  "iat": 1609459200,
  "exp": 1609462800
}
```

### 3. Client Usage

Use `turnutils_uclient` with JWT authentication:

```bash
# Basic JWT authentication
./turnutils_uclient -A "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." -v 127.0.0.1

# With additional options
./turnutils_uclient -A "your_jwt_token_here" -v -p 3478 127.0.0.1
```

### 4. Server Configuration

The server automatically:
1. Extracts JWT tokens from STUN messages
2. Validates tokens using available public keys
3. Extracts username and realm from validated tokens
4. Sets session credentials based on JWT claims

No additional server configuration is required beyond placing public key files in the search locations.

## API Reference

### Core Functions

```c
// Initialize JWT subsystem
int coturn_jwt_init(void);

// Cleanup JWT subsystem
void coturn_jwt_cleanup(void);

// Validate JWT token
int coturn_jwt_validate_token(const char* token, const char* public_key_file);

// Create JWT token
char* coturn_jwt_create_token(const char* username, const char* realm, 
                              int ttl, const char* private_key_file);

// Extract claims
char* coturn_jwt_get_username(const char* token, const char* public_key_file);
char* coturn_jwt_get_realm(const char* token, const char* public_key_file);
```

### STUN Integration

```c
// Add JWT token to STUN message
int add_jwt_token_to_stun_msg(uint8_t* buf, size_t* len, const char* jwt_token);

// Extract JWT token from STUN message
char* extract_jwt_token_from_stun_msg(const uint8_t* buf, size_t len);
```

## Integration Details

### Client Integration

The client integration adds:
- New command-line option `-A` for JWT token input
- Automatic token injection into ALLOCATE requests
- Global variables for JWT state management

### Server Integration

The server integration provides:
- Automatic JWT token extraction from STUN messages
- Multi-key validation with fallback
- Session credential setting from JWT claims
- Proper error handling and logging

## STUN Attribute Specification

- **Attribute Type**: 0x8040 (custom attribute)
- **Maximum Length**: 400 bytes
- **Format**: Raw JWT token string
- **Usage**: Transmitted in STUN ALLOCATE requests

## Security Considerations

1. **Key Management**: Keep private keys secure and use proper file permissions
2. **Token Expiration**: Implement appropriate token expiration times
3. **Transport Security**: Use TLS/DTLS for token transmission
4. **Key Rotation**: Regularly rotate signing keys
5. **Validation**: Always validate tokens server-side

## Build Requirements

- OpenSSL (for cryptographic functions)
- CMake build system
- Standard C libraries

## Error Handling

The implementation provides comprehensive error handling:
- Invalid tokens return 401 Unauthorized
- Missing keys log errors and fail gracefully
- Memory allocation failures are handled safely
- All dynamically allocated memory is properly freed

## Logging

JWT operations are logged with prefixes:
- `JWT: Subsystem initialized`
- `JWT: Found token in ALLOCATE request`
- `JWT: Token validated successfully`
- `JWT: Username from token: <username>`
- `JWT: Realm from token: <realm>`

## Testing

Test the implementation with:

```bash
# Generate test keys
cd src/jwt && ./generate_sample_keys.sh

# Build the project
cd ../.. && cmake --build build

# Run client with JWT
./bin/turnutils_uclient -A "test_jwt_token" -v 127.0.0.1
```

## Troubleshooting

1. **Token validation fails**: Check public key file locations and permissions
2. **Compilation errors**: Ensure all dependencies are installed
3. **Runtime errors**: Check logs for JWT-specific error messages
4. **Key not found**: Verify key files are in correct search locations

## Integration with Existing Authentication

JWT authentication can coexist with existing authentication methods. The server will attempt JWT validation first, falling back to standard authentication if no JWT token is present.
