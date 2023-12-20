#
# Copyright 2023 Yi Huang. All Rights Reserved.
#

import json
from Crypto.Cipher import AES

SFP_KEY_CELL = 8
KEY_DB_NAME = 'server.db'

KEY_A = 0x82d070e5ca3bfbb1b814958fb84bca11
KEY_B = 0x6f07ce556043b0df2832f1e7fce031ea
IV = 0x94b14cd6b035d59e7de03f5b40ed0cce


def read_key_db(file_path):
  with open(file_path, 'rb') as f:
    contents = f.read()
  return contents


def write_key_pair(pri_key_path, pri_key, pub_key_path, pub_key):
  with open(pri_key_path, 'w') as f:
    f.write(pri_key)

  with open(pub_key_path, 'w') as f:
    f.write(pub_key)


if __name__ == '__main__':
  file_path = KEY_DB_NAME
  cipher_bytes = read_key_db(file_path)

  key_byte_a = KEY_A.to_bytes(16, byteorder='big')
  key_byte_b = KEY_B.to_bytes(16, byteorder='big')
  key_byte = key_byte_a + key_byte_b
  iv_byte = IV.to_bytes(16, byteorder='big')

  cipher = AES.new(key_byte, AES.MODE_CBC, iv_byte)
  plain_bytes = cipher.decrypt(cipher_bytes)
  contents = plain_bytes.decode('UTF-8')

  print(contents, len(contents))
  res = json.loads(contents)

  len_1024_list = res["l1024"]
  for i in range(SFP_KEY_CELL):
    key_pair = len_1024_list[i]
    pri_key = key_pair[0]
    pub_key = key_pair[1]

    pri_key_path = "./secure_bootx/l1024/%i/srk.pri" % (i + 1)
    pub_key_path = "./secure_bootx/l1024/%i/srk.pub" % (i + 1)
    write_key_pair(pri_key_path, pri_key, pub_key_path, pub_key)

  len_2048_list = res["l2048"]
  for i in range(SFP_KEY_CELL):
    key_pair = len_2048_list[i]
    pri_key = key_pair[0]
    pub_key = key_pair[1]

    pri_key_path = "./secure_bootx/l2048/%i/srk.pri" % (i + 1)
    pub_key_path = "./secure_bootx/l2048/%i/srk.pub" % (i + 1)
    write_key_pair(pri_key_path, pri_key, pub_key_path, pub_key)
