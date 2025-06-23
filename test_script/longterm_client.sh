#!/bin/bash
ROOT_DIR=$(git rev-parse --show-toplevel)
echo "Root directory: $ROOT_DIR"    
$ROOT_DIR/build/bin/turnutils_uclient \
    -r camipc.viettel.ai \
    127.0.0.1 \
    -p 3478 \
    -v \
    -n 1 \
    -m 1 \
    -u camipcadmin \
    -w MakeViettelGreatAgain \
    -e 127.0.0.1 \
    -y
