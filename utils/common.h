//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#ifndef UTILS_COMMON_H_
#define UTILS_COMMON_H_

#define SERVER_URL  "localhost"
#define SERVER_ADDR "0.0.0.0"
#define SERVER_PORT 50051

#define RPC_FAILURE_MSG "FAILURE"

#define LEN_1024_KEY_SET 0
#define LEN_2048_KEY_SET 1
#define RSA_1024_KEY_SET 1024
#define RSA_2048_KEY_SET 2048

#define BYTE_HEX_STR_SIZE 3
#define CRYPTO_HASH_CTX_SIZE 0x400
#define SHA256_DIGEST_LENGTH 32
#define PUB_KEY_STRLEN_THLD 150

#define KEY_SIZE_BYTES 1024
#define SUPRT_KEY_ID   8
#define SUPRT_KEY_SET  2
#define SUPRT_PUB_TYPE 2

#define JOB_LX2160_PUB 0
#define JOB_J5_PUB_PEM 1
#define JOB_J5_PUB_DER 2
#define JOB_J5_PUB_SIG 3

#define PUB_PEM_TYPE   "pem"
#define PUB_DER_TYPE   "der"
#define PUB_SIG_TYPE   "sign"
#define NXP_PUB_TYPE   "nxp"
#define AURIX_PUB_TYPE "aurix"

#define FMT_RSA_SIGN_STR 's'
#define FMT_RSA_SIGN_BYT 'b'
#define FMT_RSA_SIGN_SSL 'l'

#define FMT_RSA_PUB_STR 's'
#define FMT_RSA_PUB_BYT 'b'
#define FMT_RSA_PUB_NUM 'n'

typedef struct {
  void* pri_key;
  char pub_key[KEY_SIZE_BYTES];
} ServerKeyPair;

typedef struct {
  char pub_key_pem[KEY_SIZE_BYTES];
  char pub_key_der[KEY_SIZE_BYTES];
  char pub_key_der_sign[KEY_SIZE_BYTES];
} ServerPubkeyPack;

typedef struct {
  char n[KEY_SIZE_BYTES];
  char e[KEY_SIZE_BYTES];
} PubBigNum;

#endif  // UTILS_COMMON_H_
