#!/bin/bash

# Generate RSA key pairs for JWT authentication
# This script creates private and public key files for JWT signing and validation

echo "Generating RSA key pairs for JWT authentication..."

# Generate private key (2048 bits)
echo "1. Generating private key (2048 bits)..."
openssl genrsa -out private_key.pem 2048

if [ $? -eq 0 ]; then
    echo "✓ Private key generated: private_key.pem"
else
    echo "✗ Failed to generate private key"
    exit 1
fi

# Generate public key from private key
echo "2. Extracting public key..."
openssl rsa -in private_key.pem -pubout -out public.pem

if [ $? -eq 0 ]; then
    echo "✓ Public key generated: public.pem"
else
    echo "✗ Failed to generate public key"
    exit 1
fi

# Also create public_key.pem as an alternative name
cp public.pem public_key.pem
echo "✓ Alternative public key created: public_key.pem"

# Set appropriate permissions
chmod 600 private_key.pem
chmod 644 public.pem public_key.pem

echo ""
echo "Key generation completed successfully!"
echo ""
echo "Files created:"
echo "  - private_key.pem (private key for signing JWT tokens)"
echo "  - public.pem (public key for validating JWT tokens)"
echo "  - public_key.pem (alternative name for public key)"
echo ""
echo "Usage:"
echo "  Server: Place public key files in src/jwt/, ./jwt/, or /etc/coturn/jwt/"
echo "  Client: Use JWT tokens signed with the private key"
echo ""
echo "Security note: Keep private_key.pem secure and never share it!"
echo "Only distribute public key files for token validation." 