#!/bin/bash

SFP_KEY_CELL=8
GEN_KEY_DIR="secure_boot"

KEY_1024_DIR="l1024"
KEY_2048_DIR="l2048"

PUB_KEY_FILE="srk.pub"
PRI_KEY_FILE="srk.pri"

mkdir ./${GEN_KEY_DIR}
mkdir ./${GEN_KEY_DIR}/${KEY_1024_DIR}
mkdir ./${GEN_KEY_DIR}/${KEY_2048_DIR}

for i in $(seq 1 $SFP_KEY_CELL); do
  ./gen_keys 1024
  mkdir ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i
  mv ${PUB_KEY_FILE} ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i/
  mv ${PRI_KEY_FILE} ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i/

  if [ $i -eq 1 ]; then
    cp ./test_key/srk_1024.pub ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i/srk.pub
    cp ./test_key/srk_1024.pri ./${GEN_KEY_DIR}/${KEY_1024_DIR}/$i/srk.pri
  fi
done

for i in $(seq 1 $SFP_KEY_CELL); do
  ./gen_keys 2048
  mkdir ./${GEN_KEY_DIR}/${KEY_2048_DIR}/$i
  mv ${PUB_KEY_FILE} ./${GEN_KEY_DIR}/${KEY_2048_DIR}/$i/
  mv ${PRI_KEY_FILE} ./${GEN_KEY_DIR}/${KEY_2048_DIR}/$i/

  if [ $i -eq 1 ]; then
    cp ./test_key/srk_2048.pri ./${GEN_KEY_DIR}/${KEY_2048_DIR}/$i/srk.pri
  fi
done

python3 gen_key_db.py
