[![Docker CI](https://github.com/coturn/coturn/actions/workflows/docker.yml/badge.svg  "Docker CI")](https://github.com/coturn/coturn/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/coturn/coturn?label=Docker%20Hub%20pulls "Docker Hub pulls")](https://hub.docker.com/r/coturn/coturn)

[Docker Hub](https://hub.docker.com/r/coturn/coturn)
| [GitHub Container Registry](https://github.com/orgs/coturn/packages/container/package/coturn)
| [Quay.io](https://quay.io/repository/coturn/coturn)

# Coturn TURN server #

coturn is a free open source implementation of TURN and STUN Server.
The TURN Server is a VoIP media traffic NAT traversal server and gateway.

## Installing / Getting started

Linux distros may have a version of coturn which you can install by
```
apt install coturn
turnserver --log-file stdout
```

Or run coturn using docker container:
```
docker run -d -p 3478:3478 -p 3478:3478/udp -p 5349:5349 -p 5349:5349/udp -p 49152-65535:49152-65535/udp coturn/coturn
```
See more details about using docker container [Docker Readme](https://github.com/coturn/coturn/blob/master/docker/coturn/README.md)


## Developing

### Dependencies

coturn requires following dependencies to be installed first
- libevent2

Optional
- openssl (to support TLS and DTLS, authorized STUN and TURN)
- libmicrohttp and [prometheus-client-c](https://github.com/digitalocean/prometheus-client-c) (prometheus interface)
- MariaDB/MySQL (user database)
- [Hiredis](https://github.com/redis/hiredis) (user database, monitoring)
- SQLite (user database)
- PostgreSQL (user database)

### Building
```shell
git clone git@github.com:coturn/coturn.git
cd coturn
./configure
make
```


## Features

STUN specs:

  * [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489) - "classic" STUN
  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - base "new" STUN specs
  * [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769) - test vectors for STUN protocol testing
  * [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) - NAT behavior discovery support
  * [RFC 7443](https://datatracker.ietf.org/doc/html/rfc7443) - ALPN support for STUN & TURN
  * [RFC 7635](https://datatracker.ietf.org/doc/html/rfc7635) - oAuth third-party TURN/STUN authorization
  
TURN specs:

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - base TURN specs
  * [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062) - TCP relaying TURN extension
  * [RFC 6156](https://datatracker.ietf.org/doc/html/rfc6156) - IPv6 extension for TURN
  * [RFC 7443](https://datatracker.ietf.org/doc/html/rfc7443) - ALPN support for STUN & TURN
  * [RFC 7635](https://datatracker.ietf.org/doc/html/rfc7635) - oAuth third-party TURN/STUN authorization
  * [RFC 8016](https://datatracker.ietf.org/doc/html/rfc8016) - Mobility with Traversal Using Relays around NAT (TURN)
  * DTLS support (http://tools.ietf.org/html/draft-petithuguenin-tram-turn-dtls-00)
  * TURN REST API (http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00)
  * Origin field in TURN (Multi-tenant TURN Server) (https://tools.ietf.org/html/draft-ietf-tram-stun-origin-06)
  * TURN Bandwidth draft specs (http://tools.ietf.org/html/draft-thomson-tram-turn-bandwidth-01)
  * TURN-bis (with dual allocation) draft specs (http://tools.ietf.org/html/draft-ietf-tram-turnbis-04)

ICE and related specs:

  * [RFC 5245](https://datatracker.ietf.org/doc/html/rfc5245) - ICE
  * [RFC 5768](https://datatracker.ietf.org/doc/html/rfc5768) – ICE–SIP
  * [RFC 6336](https://datatracker.ietf.org/doc/html/rfc6336) – ICE–IANA Registry
  * [RFC 6544](https://datatracker.ietf.org/doc/html/rfc6544) – ICE–TCP
  * [RFC 5928](https://datatracker.ietf.org/doc/html/rfc5928) - TURN Resolution Mechanism

The implementation fully supports the following client-to-TURN-server protocols:

  * UDP (per [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766))
  * TCP (per [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) and [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062))
  * TLS (per [RFC 5766](https://datatracker.ietf.org/doc/html/rfc) and [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062)): including TLS1.3; ECDHE is supported.
  * DTLS1.0 and DTLS1.2 (http://tools.ietf.org/html/draft-petithuguenin-tram-turn-dtls-00)
  * SCTP (experimental implementation).

Relay protocols:

  * UDP (per [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766))
  * TCP (per [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062))

User databases (for user repository, with passwords or keys, if authentication is required):

  * SQLite
  * MariaDB/MySQL
  * PostgreSQL
  * Redis
  * MongoDB
  
  
Management interfaces:
 * telnet cli 
 * HTTPS interface


Monitoring:
 * Redis can be used for status and statistics storage and notification
 * [prometheus](https://prometheus.io/) interface (unavailable on apt package)

Message integrity digest algorithms:

  * HMAC-SHA1, with MD5-hashed keys (as required by STUN and TURN standards)

TURN authentication mechanisms:

  * 'classic' long-term credentials mechanism;
  * TURN REST API (a modification of the long-term mechanism, for time-limited secret-based authentication, for WebRTC applications: http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00);
  * experimental third-party oAuth-based client authorization option;
  * **JWT (JSON Web Token) authentication** - RS256 signature validation with custom STUN attribute (0x8040);

Performance and Load Balancing:

When used as a part of an ICE solution, for VoIP connectivity, this TURN server can handle thousands simultaneous calls per CPU (when TURN protocol is used) or tens of thousands calls when only STUN protocol is used. For virtually unlimited scalability a load balancing scheme can be used. The load balancing can be implemented with the following tools (either one or a combination of them):

  * DNS SRV based load balancing;
  * built-in 300 ALTERNATE-SERVER mechanism (requires 300 response support by the TURN client);
  * network load-balancer server.

Traffic bandwidth limitation and congestion avoidance algorithms implemented.

Target platforms:

  * Linux (Debian, Ubuntu, Mint, CentOS, Fedora, Redhat, Amazon Linux, Arch Linux, OpenSUSE)
  * BSD (FreeBSD, NetBSD, OpenBSD, DragonFlyBSD)
  * Solaris 11
  * Mac OS X
  * Cygwin (for non-production R&D purposes)
  * Windows (native with, e.g., MSVC toolchain)

This project can be successfully used on other `*NIX` platforms, too, but that is not officially supported.

The implementation is supposed to be simple, easy to install and configure. The project focuses on performance, scalability and simplicity. The aim is to provide an enterprise-grade TURN solution.

To achieve high performance and scalability, the TURN server is implemented with the following features:

  * High-performance industrial-strength Network IO engine libevent2 is used
  * Configurable multi-threading model implemented to allow full usage of available CPU resources (if OS allows multi-threading)
  * Multiple listening and relay addresses can be configured
  * Efficient memory model used
  * The TURN project code can be used in a custom proprietary networking environment. In the TURN server code, an abstract networking API is used. Only couple files in the project have to be re-written to plug-in the TURN server into a proprietary environment. With this project, only implementation for standard UNIX Networking/IO API is provided, but the  user can implement any other environment. The TURN server code was originally developed for a high-performance proprietary corporate environment, then adopted for UNIX Networking API
  * The TURN server works as a user space process, without imposing any special requirements on the system


## JWT Authentication Usage

### Overview

Coturn supports JWT (JSON Web Token) authentication using RS256 signatures. JWT tokens are transmitted via a custom STUN attribute (0x8040) supporting tokens up to 400 bytes.

### 1. Key Generation

Generate RSA key pairs for JWT signing and validation:

```bash
cd src/jwt
./generate_sample_keys.sh
```

This creates:
- `private_key.pem` - Private key for token signing
- `public.pem` - Public key for token validation

### 2. JWT Token Format

JWT tokens should include these claims:
```json
{
  "username": "testuser",
  "iss": "coturn-server",
  "aud": "coturn-client",
  "iat": 1609459200,
  "exp": 1609462800
}
```

**Important**: 
- JWT tokens are used **only for authentication validation**, not for realm information
- Realm is handled through standard STUN protocol attributes as in traditional TURN authentication
- The `realm` claim in JWT is optional and will be ignored - use server's `-r` option to set realm

### 3. Server Configuration

Start the TURN server with JWT authentication:

```bash
# Basic JWT server
./turnserver --jwt=1 -v -r turn

# With specific listening configuration
./turnserver --jwt=1 -v -r turn -L 127.0.0.1 --listening-port 3478

# Background mode
./turnserver --jwt=1 -v -r turn -L 127.0.0.1 --listening-port 3478 &
```

**Key Requirements:**
- Place public key files in one of these locations:
  - `src/jwt/public.pem`
  - `./jwt/public_key.pem` 
  - `/etc/coturn/jwt/public_key.pem`
  - `./public_key.pem`

### 4. Client Usage

Use `turnutils_uclient` with JWT authentication:

```bash
# Basic JWT client
./turnutils_uclient -A "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." -v -y 127.0.0.1

# With specific port
./turnutils_uclient -A "your_jwt_token_here" -v -p 3478 -y 127.0.0.1

# Complete example
./turnutils_uclient -A "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwicmVhbG0iOiJ0ZXN0cmVhbG0iLCJpc3MiOiJjb3R1cm4tc2VydmVyIiwiYXVkIjoiY290dXJuLWNsaWVudCJ9.signature" -v -y 127.0.0.1
```

### 5. JWT Integration Features

- **Custom STUN Attribute**: JWT tokens use STUN attribute 0x8040
- **Multiple Key Support**: Automatic fallback across multiple public key files  
- **Username Extraction**: Automatic extraction from JWT claims
- **STUN Protocol Realm**: Realm handled via standard STUN protocol (not from JWT)
- **RS256 Validation**: Secure signature validation with OpenSSL
- **Error Handling**: Comprehensive error messages and logging

### 6. Building with JWT Support

```bash
# Build the complete project
cd coturn
mkdir build && cd build
cmake ..
make -j$(nproc)

# JWT library will be automatically built as 'turnjwt'
# Server binary: build/bin/turnserver
# Client binary: build/bin/turnutils_uclient
```

### 7. Testing JWT Implementation

```bash
# 1. Generate keys
cd src/jwt && ./generate_sample_keys.sh

# 2. Start server in one terminal
./build/bin/turnserver --jwt=1 -v -r turn -L 127.0.0.1

# 3. Test client in another terminal
./build/bin/turnutils_uclient -A "test_jwt_token" -v -y 127.0.0.1
```

### 8. JWT Log Messages

When JWT authentication is working, you'll see these log messages:

**Server side:**
```
JWT authentication mode enabled
JWT: Token extracted from STUN message
JWT: Token validated successfully with key: src/jwt/public.pem
JWT: Username from token: testuser
NOTE: Realm will be handled through standard STUN protocol
```

**Client side:**
```
JWT: Successfully added token to STUN message (length: 256)
JWT token added to ALLOCATE request
```

### 9. Troubleshooting JWT

**Common Issues:**
- **"JWT Token Required"**: Server is in JWT mode but no token provided
- **"Invalid JWT Token"**: Token signature validation failed
- **"No realm in token (this is expected - use STUN realm instead)"**: Normal behavior - realm comes from STUN protocol
- **"Connection refused"**: Server not running or wrong port

**Debug Steps:**
1. Verify public key files are in correct locations
2. Check server is started with `--jwt=1` option
3. Ensure JWT token is properly formatted
4. Check server logs for detailed error messages

## Links

- Project homepage: https://coturn.github.io/
- Repository: https://github.com/coturn/coturn/
- Issue tracker: https://github.com/coturn/coturn/issues
- Google group: https://groups.google.com/forum/#!forum/turn-server-project-rfc5766-turn-server
