#!/bin/bash

SFP_KEY_CELL=8

GEN_KEY_SRC="secure_boot"
GEN_KEY_DST="secure_bootx"

KEY_1024_DIR="l1024"
KEY_2048_DIR="l2048"

./gen_key_db.sh
./deploy_key_db.sh

for i in $(seq 1 $SFP_KEY_CELL); do
  diff ./${GEN_KEY_SRC}/${KEY_1024_DIR}/$i/srk.pri ./${GEN_KEY_DST}/${KEY_1024_DIR}/$i/srk.pri | wc
  diff ./${GEN_KEY_SRC}/${KEY_1024_DIR}/$i/srk.pub ./${GEN_KEY_DST}/${KEY_1024_DIR}/$i/srk.pub | wc
done

for i in $(seq 1 $SFP_KEY_CELL); do
  diff ./${GEN_KEY_SRC}/${KEY_2048_DIR}/$i/srk.pri ./${GEN_KEY_DST}/${KEY_2048_DIR}/$i/srk.pri | wc
  diff ./${GEN_KEY_SRC}/${KEY_2048_DIR}/$i/srk.pub ./${GEN_KEY_DST}/${KEY_2048_DIR}/$i/srk.pub | wc
done

rm -rf ./${GEN_KEY_SRC}
rm -rf ./${GEN_KEY_DST}
