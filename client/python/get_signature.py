# Copyright 2023 Yi Huang. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Python implementation of the gRPC signserver.CodeSigning client."""

import sys
import os
import logging
import argparse
import binascii
import hashlib
import string

import grpc
import signserver_pb2
import signserver_pb2_grpc

SERVER_PORT = "50051"
SERVER_URL = "localhost"

RSA_1024_KEY_SET = 1024
RSA_2048_KEY_SET = 2048
SHA256_DIGEST_LENGTH = 32
RESP_FAIL_STR = "FAILURE"


def process_args(orig_file, hash_file, hash_str):
    arg_cnt = 0
    if orig_file is not None: arg_cnt += 1
    if hash_file is not None: arg_cnt += 1
    if hash_str is not None: arg_cnt += 1
    if arg_cnt != 1:
        return None

    if orig_file is not None:
        if not os.path.exists(orig_file):
            return None
        with open(orig_file, 'rb') as f:
            data_bytes = f.read()
            if len(data_bytes) == 0:
                return None
            msg = hashlib.sha256()
            msg.update(data_bytes)
            hash_bytes = msg.digest()
            return binascii.b2a_hex(hash_bytes)
    elif hash_file is not None:
        if not os.path.exists(hash_file):
            return None
        with open(hash_file, 'rb') as f:
            hash_bytes = f.read()
            if len(hash_bytes) != SHA256_DIGEST_LENGTH:
                return None
            return binascii.b2a_hex(hash_bytes)
    else:
        for h in hash_str:
            if h not in string.hexdigits:
                return None
        return hash_str


def run(server_info, hash_str, key_set, key_id, disp_fmt, tag_name):
    if disp_fmt != 'b' and disp_fmt != 's' and disp_fmt != 'l':
        return False

    if disp_fmt == 'l' and tag_name is None:
        return False

    if key_set != RSA_1024_KEY_SET and key_set != RSA_2048_KEY_SET:
        return False

    if key_id < 1 or key_id > 8 or hash_str is None:
        return False

    if len(hash_str) != SHA256_DIGEST_LENGTH * 2:
        return False

    with grpc.insecure_channel(server_info) as channel:
        stub = signserver_pb2_grpc.CodeSigningStub(channel)
        request = signserver_pb2.RsaSignRequest(hash_str=hash_str,
                                                key_set=key_set,
                                                key_id=key_id)
        response = stub.GetRsaSignature(request)

    if response.signature == RESP_FAIL_STR:
        return False

    if disp_fmt == 'b':
        sig_bytes = binascii.unhexlify(response.signature)
        sys.stdout.buffer.write(sig_bytes)
    elif disp_fmt == 's':
        print(response.signature)
    else:
        print("RSA-SHA256({})= {}".format(tag_name, response.signature))
    return True


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser()

    # Required option with default value
    parser.add_argument('-a', '--addr',
                        help='Server IP address',
                        default=SERVER_URL)
    parser.add_argument('-p', '--port',
                        help='Server port number',
                        default=SERVER_PORT)

    # Required option with user input value
    parser.add_argument('-l', '--length',
                        help='Support key length either 2048 or 1024',
                        type=int,
                        required=True)
    parser.add_argument('-i', '--id',
                        help='Key ID range from 1 to 8',
                        type=int,
                        required=True)

    # Required option choose one in the list
    parser.add_argument('-o', '--orig_file',
                        help='Path of the original file to get signature',
                        default=None)
    parser.add_argument('-d', '--hash_file',
                        help='Path of the hash file to get signature',
                        default=None)
    parser.add_argument('-x', '--hash_str',
                        help='Hash value as hex string to get signature',
                        default=None)

    # Optional option with default value
    parser.add_argument('-f', '--fmt',
                        help='Display format [s: text, b: binary, l: openssl]',
                        default='s')
    parser.add_argument('-t', '--tag',
                        help='Tag name for the Openssl format signature',
                        default=None)

    args = parser.parse_args()
    server_info = "{}:{}".format(args.addr, args.port)
    hash_str = process_args(args.orig_file, args.hash_file, args.hash_str)

    if args.orig_file is not None:
        tag_name = os.path.basename(args.orig_file)
    else:
        tag_name = args.tag

    if not run(server_info, hash_str, args.length, args.id, args.fmt, tag_name):
        print("Failed to get signature ...")
        parser.print_help()
        sys.exit(1)
