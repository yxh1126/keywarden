#!/bin/bash

SFP_KEY_CELL=8
GEN_KEY_DIR="secure_bootx"

KEY_1024_DIR="l1024"
KEY_2048_DIR="l2048"

mkdir ./${GEN_KEY_DIR}
mkdir ./${GEN_KEY_DIR}/${KEY_1024_DIR}
mkdir ./${GEN_KEY_DIR}/${KEY_2048_DIR}

for i in $(seq 1 $SFP_KEY_CELL); do
  mkdir ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i
done

for i in $(seq 1 $SFP_KEY_CELL); do
  mkdir ./${GEN_KEY_DIR}/${KEY_2048_DIR}/$i
done

python3 deploy_key_db.py
