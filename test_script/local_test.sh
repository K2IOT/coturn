#!/bin/bash

# --log-file=stdout --verbose --no-cli --no-tls --no-dtls --fingerprint --realm=camipc.viettel.ai --user=camipcadmin:MakeViettelGreatAgain --lt-cred-mech --listening-port=3478 --tls-listening-port=5349 --min-port=10000 --max-port=65535 --syslog --allow-loopback-peers
./build/bin/turnutils_uclient -r camipc.viettel.ai 127.0.0.1 -p 3478 -v -n 1 -m 1 -u camipcadmin -w MakeViettelGreatAgain -e 127.0.0.1 -y
