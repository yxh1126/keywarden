#
# Copyright 2023 Inceptio Technology. All Rights Reserved.
#

import json
from Crypto.Cipher import AES

SFP_KEY_CELL = 8
AES_BLOCK_SIZE = 16
KEY_DB_NAME = 'server.db'
PADDING_CHAR = ' '

KEY_A = 0x82d070e5ca3bfbb1b814958fb84bca11
KEY_B = 0x6f07ce556043b0df2832f1e7fce031ea
IV = 0x94b14cd6b035d59e7de03f5b40ed0cce


def read_key_pair(pri_key_path, pub_key_path):
  with open(pri_key_path, 'r') as f:
    pri_key = f.read()
  with open(pub_key_path, 'r') as f:
    pub_key = f.read()

  return (pri_key, pub_key)


def creat_key_pkg(key_data_dic):
  # For len 1024 key pair
  l1024_key_list = []
  for i in range(SFP_KEY_CELL):
    pri_key_path = "./secure_boot/l1024/%i/srk.pri" % (i + 1)
    pub_key_path = "./secure_boot/l1024/%i/srk.pub" % (i + 1)

    key_pair = read_key_pair(pri_key_path, pub_key_path)
    l1024_key_list.append(key_pair)

  # For len 2048 key pair
  l2048_key_list = []
  for i in range(SFP_KEY_CELL):
    pri_key_path = "./secure_boot/l2048/%i/srk.pri" % (i + 1)
    pub_key_path = "./secure_boot/l2048/%i/srk.pub" % (i + 1)

    key_pair = read_key_pair(pri_key_path, pub_key_path)
    l2048_key_list.append(key_pair)

  key_data_dic["l1024"] = l1024_key_list
  key_data_dic["l2048"] = l2048_key_list


def padding(entry):
  padded = entry + (AES_BLOCK_SIZE - len(entry) % AES_BLOCK_SIZE) * PADDING_CHAR
  return padded


if __name__ == '__main__':
  key_data_dic = {}
  file_path = KEY_DB_NAME

  creat_key_pkg(key_data_dic)
  key_data_obj = json.dumps(key_data_dic)

  key_byte_a = KEY_A.to_bytes(16, byteorder='big')
  key_byte_b = KEY_B.to_bytes(16, byteorder='big')
  key_byte = key_byte_a + key_byte_b
  iv_byte = IV.to_bytes(16, byteorder='big')

  key_data_obj = padding(key_data_obj)
  plain_bytes = key_data_obj.encode('UTF-8')

  cipher = AES.new(key_byte, AES.MODE_CBC, iv_byte)
  cipher_bytes = cipher.encrypt(plain_bytes)

  with open(file_path, 'wb') as fp:
    fp.write(cipher_bytes)
