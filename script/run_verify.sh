#!/bin/bash

# 1. Server key pair self verification
printf "[1] Server pri sign and local pub verify\n"
./verify_sign_server.sh | grep 'Successful verification!'
./verify_sign_server.sh | grep 'Successful verification!' | wc --lines

# 2. Self dev hash function v.s. NXP dev hash function
printf "\n[2] Hash function check\n"
./verify_sign_server.sh | grep 'differ'
./verify_sign_server.sh | grep 'differ' | wc

# 3. Write all the hash value in the key server to file
printf "\n[3] Write hash value to file\n"
./verify_sign_server.sh | grep -A 1 'SRK (Public Key) Hash' > all_hash.log
printf "write done...\n"

# 4. Local signature v.s. Server signature
printf "\n[4] Local pub and pri key compare with server\n"
./check_sign_key.sh | grep 'differ'
./check_sign_key.sh | grep 'differ' | wc
