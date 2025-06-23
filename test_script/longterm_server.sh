#!/bin/bash
ROOT_DIR=$(git rev-parse --show-toplevel)
echo "Root directory: $ROOT_DIR"

# Kill all turnserver processes
pkill -f "turnserver"

# Kill all turnutils_uclient processes
pkill -f "turnutils_uclient"

# Wait for processes to be killed
sleep 1

# Clean and rebuild the project
echo "🧹 Cleaning build directory..."
rm -rf build/
rm -rf cmake-build-debug/

echo "🔨 Creating build directory and configuring..."
mkdir -p build
cd build

echo "⚙️ Running cmake configuration..."
cmake ..

echo "🏗️ Building project..."
make -j$(nproc)

echo "📁 Going back to project root..."
cd ..

echo "🚀 Starting TURN server..."
$ROOT_DIR/build/bin/turnserver \
  --log-file=stdout \
  --verbose \
  --no-cli \
  --no-tls \
  --no-dtls \
  --realm=camipc.viettel.ai \
  --user=camipcadmin:MakeViettelGreatAgain \
  --lt-cred-mech \
  --listening-port=3478 \
  --tls-listening-port=5349 \
  --min-port=10000 \
  --max-port=65535 \
  --syslog \
  --allow-loopback-peers \
  --fingerprint


