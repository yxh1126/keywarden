# Copyright 2023 Inceptio Technology. All Rights Reserved.
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

import logging
import argparse
import sys

import grpc
import signserver_pb2
import signserver_pb2_grpc

SERVER_PORT = "50051"
SERVER_URL = "localhost"

RSA_1024_KEY_SET = 1024
RSA_2048_KEY_SET = 2048
KEY_TYPE = {'nxp': 0, 'pem': 1, 'der': 2, 'sign': 3, 'aurix': 2}
RESP_FAIL_STR = "FAILURE"


def get_pub_modulus(pubkey_der, key_set):
    if key_set == RSA_2048_KEY_SET:
        skip_bytes = 33
    elif key_set == RSA_1024_KEY_SET:
        skip_bytes = 29
    else:
        return (None, None)

    mod_bytes = key_set // 8
    exp_bytes = 3

    pub_mod = pubkey_der[skip_bytes * 2 : skip_bytes * 2 + mod_bytes * 2]
    pub_exp = pubkey_der[-exp_bytes * 2 :]
    return (pub_mod, pub_exp)


def run(server_info, key_set, key_id, key_type):
    if key_set != RSA_1024_KEY_SET and key_set != RSA_2048_KEY_SET:
        return False

    if key_id < 1 or key_id > 8:
        return False

    if key_type in KEY_TYPE:
        key_type_val = KEY_TYPE[key_type]
    else:
        return False

    with grpc.insecure_channel(server_info) as channel:
        stub = signserver_pb2_grpc.CodeSigningStub(channel)
        request = signserver_pb2.RsaPubkeyRequest(key_set=key_set,
                                                  key_id=key_id,
                                                  key_type=key_type_val)
        response = stub.GetRsaPublicKey(request)

    if response.public_key == RESP_FAIL_STR:
        return False

    if key_type == "aurix":
        (pub_mod, pub_exp) = get_pub_modulus(response.public_key, key_set)
        if pub_mod is None:
            return False
        print('n = 0x' + pub_mod)
        print('e = 0x' + pub_exp)
    else:
        print(response.public_key)
    return True


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--addr',
                        help='Server IP address',
                        default=SERVER_URL)
    parser.add_argument('-p', '--port',
                        help='Server port number',
                        default=SERVER_PORT)
    parser.add_argument('-l', '--length',
                        help='Support key length either 2048 or 1024',
                        type=int,
                        required=True)
    parser.add_argument('-i', '--id',
                        help='Key ID range from 1 to 8',
                        type=int,
                        required=True)
    parser.add_argument('-t', '--type',
                        help='Public key type: [pem, der, sign, nxp, aurix]',
                        required=True)

    args = parser.parse_args()
    server_info = "{}:{}".format(args.addr, args.port)

    if not run(server_info, args.length, args.id, args.type):
        print("Failed to get public key ...")
        parser.print_help()
        sys.exit(1)
