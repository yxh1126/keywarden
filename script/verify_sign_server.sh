#!/bin/bash

SFP_KEY_CELL=8

# SERVER_IP_ADDR='localhost'
SERVER_IP_ADDR='10.8.50.228'

for i in $(seq 1 $SFP_KEY_CELL); do
  ./get_pub_key --srk_hash 1024 $i $SERVER_IP_ADDR
  cat srk_hash.txt | grep SRKHR > abc.txt
  ./gen_sign_client ./test_set/source.hash 1024 $i $SERVER_IP_ADDR
  ./verify_sign ./test_set/source.hash sign.out srk.pub

  ./create_hdr_esbc --hash ./input_files/uni_sign/lx2160/test_input_file | grep SRKHR > efg.txt
  diff --brief abc.txt efg.txt

  if [ $i -eq 1 ]; then
    diff --brief ./efuse/srk.pub ./srk.pub
  fi
done

for i in $(seq 1 $SFP_KEY_CELL); do
  ./get_pub_key --srk_hash 2048 $i $SERVER_IP_ADDR
  cat srk_hash.txt | grep SRKHR > abc.txt
  ./gen_sign_client ./test_set/source.hash 2048 $i $SERVER_IP_ADDR
  ./verify_sign ./test_set/source.hash sign.out srk.pub

  ./create_hdr_esbc --hash ./input_files/uni_sign/lx2160/test_input_file | grep SRKHR > efg.txt
  diff --brief abc.txt efg.txt
done

rm abc.txt efg.txt srk.pub srk_hash.txt sign.out
