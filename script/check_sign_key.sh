#!/bin/bash

SFP_KEY_CELL=8
GEN_KEY_DST="secure_bootx"

# SERVER_IP_ADDR='localhost'
SERVER_IP_ADDR='10.8.50.228'

KEY_1024_DIR="l1024"
KEY_2048_DIR="l2048"

./deploy_key_db.sh

for i in $(seq 1 $SFP_KEY_CELL); do
  ./gen_sign ./test_set/source.hash ./${GEN_KEY_DST}/${KEY_1024_DIR}/$i/srk.pri --sign_file abc.out
  ./gen_sign_client ./test_set/source.hash 1024 $i $SERVER_IP_ADDR --sign_file efg.out
  diff --brief abc.out efg.out

  ./get_pub_key 1024 $i $SERVER_IP_ADDR
  diff --brief ./${GEN_KEY_DST}/${KEY_1024_DIR}/$i/srk.pub ./srk.pub
done

for i in $(seq 1 $SFP_KEY_CELL); do
  ./gen_sign ./test_set/source.hash ./${GEN_KEY_DST}/${KEY_2048_DIR}/$i/srk.pri --sign_file abc.out
  ./gen_sign_client ./test_set/source.hash 2048 $i $SERVER_IP_ADDR --sign_file efg.out
  diff --brief abc.out efg.out

  ./get_pub_key 2048 $i $SERVER_IP_ADDR
  diff --brief ./${GEN_KEY_DST}/${KEY_2048_DIR}/$i/srk.pub ./srk.pub
done

rm -rf ./${GEN_KEY_DST}
rm abc.out efg.out srk.pub
