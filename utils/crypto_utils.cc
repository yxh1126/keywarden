//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "utils/crypto_utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <streambuf>

#include "utils/common.h"
#include "utils/fmt_utils.h"
#include "openssl/aes.h"
#include "openssl/ssl.h"

using utils::CryptoUtils;
using utils::FmtUtils;

bool CryptoUtils::RsaSignHash(uint8_t* img_hash, uint32_t len,
                              uint8_t* rsa_sign, uint32_t* rsa_len,
                              void* pri_key_ptr) {
  int ret;
  RSA* priv_key;

  if (pri_key_ptr == NULL) {
    printf("Error in private key buffer\n");
    return false;
  }
  priv_key = reinterpret_cast<RSA*>(pri_key_ptr);

  /* Sign the Image Hash with Private Key */
  ret = RSA_sign(NID_sha256, img_hash, len, rsa_sign, rsa_len, priv_key);

  if (ret != 1) {
    printf("Error in Signing\n");
    return false;
  }
  return true;
}

bool CryptoUtils::DumpRsaPubKey(const char* key_name, char* pub_key_pem,
                                char* pub_key_der, uint8_t* pubkey_der_hash) {
  EVP_PKEY* priv_key;
  BIO *rsa_pem_bio, *pem_buff, *der_buff;
  int ret;
  char *pub_pem_buf;
  uint8_t *pub_der_buf;
  int64_t buf_len;

  if (pub_key_pem == NULL || pub_key_der == NULL || pubkey_der_hash == NULL) {
    printf("Public key buffer empty error\n");
    return false;
  }

  rsa_pem_bio = BIO_new_file(key_name, "r");
  priv_key = PEM_read_bio_PrivateKey(rsa_pem_bio, NULL, NULL, NULL);
  if (priv_key == NULL) {
    printf("Failed to read private key from key pair\n");
    return false;
  }

  pem_buff = BIO_new(BIO_s_mem());
  ret = PEM_write_bio_PUBKEY(pem_buff, priv_key);
  if (ret != 1) {
    printf("Error writing public key data in PEM format\n");
    return false;
  }

  der_buff = BIO_new(BIO_s_mem());
  ret = i2d_PUBKEY_bio(der_buff, priv_key);
  if (ret != 1) {
    printf("Error writing public key data in DER format\n");
    return false;
  }

  buf_len = BIO_get_mem_data(pem_buff, &pub_pem_buf);
  if (buf_len <= 0) {
    printf("Error dumping PEM format data\n");
    return false;
  }

  /* Copy buffer data as output */
  snprintf(pub_key_pem, strlen(pub_pem_buf) + 1, "%s", pub_pem_buf);

  buf_len = BIO_get_mem_data(der_buff, &pub_der_buf);
  if (buf_len <= 0) {
    printf("Error dumping DER format data\n");
    return false;
  }

  /* Copy and convert buffer data as output */
  if (!FmtUtils::BytesToHexString(pub_der_buf, buf_len, pub_key_der,
                                  KEY_SIZE_BYTES)) {
    printf("Error in data conversion for DER format data\n");
    return false;
  }

  /* Calculate SHA256 of the DER format data */
  GetSha256Hash(pub_der_buf, buf_len, pubkey_der_hash);

  BIO_free(rsa_pem_bio);
  BIO_free(pem_buff);
  BIO_free(der_buff);
  EVP_PKEY_free(priv_key);

  return true;
}

bool CryptoUtils::ExtractRsaPriKey(const char* key_name, void** pri_key_ptr) {
  FILE* fpriv;
  RSA* priv_key;

  /* Open the private Key */
  fpriv = fopen(key_name, "r");
  if (fpriv == NULL) {
    printf("Error in file opening %s:\n", key_name);
    return false;
  }

  priv_key = PEM_read_RSAPrivateKey(fpriv, NULL, NULL, NULL);
  fclose(fpriv);
  if (priv_key == NULL) {
    printf("Error in key reading %s:\n", key_name);
    return false;
  }
  *pri_key_ptr = reinterpret_cast<void*>(priv_key);

  return true;
}

void CryptoUtils::RsaPriKeyFree(void* pri_key_ptr) {
  RSA* priv_key = reinterpret_cast<RSA*>(pri_key_ptr);
  RSA_free(priv_key);
}

void CryptoUtils::GetSha256Hash(const void* data, uint32_t len, uint8_t* hash) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(hash, &ctx);
}

void CryptoUtils::GetSha256Hash(const std::string& data, uint8_t* hash) {
  char buffer[kBufferSize];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  size_t data_len = data.size();
  size_t offset = 0;
  while (data_len > 0) {
    if (data_len >= kBufferSize) {
      for (size_t i = 0; i < kBufferSize; i++) {
        buffer[i] = data[i + offset];
      }
      SHA256_Update(&ctx, buffer, kBufferSize);
      data_len -= kBufferSize;
      offset += kBufferSize;
    } else {
      for (size_t i = 0; i < data_len; i++) {
        buffer[i] = data[i + offset];
      }
      SHA256_Update(&ctx, buffer, data_len);
      data_len = 0;
    }
  }
  SHA256_Final(hash, &ctx);
}

std::string CryptoUtils::GetFileSha256Hash(const std::string& fpath) {
  uint8_t hash_out[SHA256_DIGEST_LENGTH];
  std::string rdtxt = FmtUtils::ReadText(fpath);
  if (rdtxt.empty()) {
    printf("Failed to read data from file ...\n");
    return "";
  }

  GetSha256Hash(rdtxt, hash_out);
  return FmtUtils::BytesToHexString(hash_out, SHA256_DIGEST_LENGTH);
}

uint8_t* CryptoUtils::Aes256Encrypt(const uint8_t* data_in, const int data_len,
                                    const uint8_t *aes_key, int* data_out_len) {
  AES_KEY enc_key;
  uint8_t *data_out, *data_in_pad;
  int pad_size, i;
  uint8_t iv[AES_BLOCK_SIZE] = {0x94, 0xb1, 0x4c, 0xd6, 0xb0, 0x35, 0xd5, 0x9e,
                                0x7d, 0xe0, 0x3f, 0x5b, 0x40, 0xed, 0x0c, 0xce};

  *data_out_len = ((data_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
  data_out = reinterpret_cast<uint8_t*>(malloc(*data_out_len));
  data_in_pad = reinterpret_cast<uint8_t*>(malloc(*data_out_len));
  std::memcpy(data_in_pad, data_in, data_len);

  pad_size = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
  for (i = 0; i < pad_size; i++) {
    *(data_in_pad + data_len + i) = ' ';
  }

  AES_set_encrypt_key(aes_key, 256, &enc_key);
  AES_cbc_encrypt(data_in_pad, data_out, *data_out_len,
                  &enc_key, iv, AES_ENCRYPT);
  free(data_in_pad);

  return data_out;
}

uint8_t* CryptoUtils::Aes256Decrypt(const char* fname_db, int* data_out_len) {
  FILE* fp;
  AES_KEY dec_key;
  int64_t byte_cnt;
  uint8_t *data_in, *data_out;
  int ret;

  uint8_t aes_key[AES_BLOCK_SIZE * 2] = {
      0x82, 0xd0, 0x70, 0xe5, 0xca, 0x3b, 0xfb, 0xb1,
      0xb8, 0x14, 0x95, 0x8f, 0xb8, 0x4b, 0xca, 0x11,
      0x6f, 0x07, 0xce, 0x55, 0x60, 0x43, 0xb0, 0xdf,
      0x28, 0x32, 0xf1, 0xe7, 0xfc, 0xe0, 0x31, 0xea};
  uint8_t iv[AES_BLOCK_SIZE] = {
      0x94, 0xb1, 0x4c, 0xd6, 0xb0, 0x35, 0xd5, 0x9e,
      0x7d, 0xe0, 0x3f, 0x5b, 0x40, 0xed, 0x0c, 0xce};

  fp = fopen(fname_db, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error in file opening: %s\n", fname_db);
    return NULL;
  }

  /* Calculating the size of the file */
  fseek(fp, 0L, SEEK_END);
  byte_cnt = ftell(fp);
  fclose(fp);

  /* Init the buffer with the calc size */
  data_in = reinterpret_cast<uint8_t*>(malloc(byte_cnt));
  data_out = reinterpret_cast<uint8_t*>(malloc(byte_cnt + 1));

  fp = fopen(fname_db, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error in file opening %s:\n", fname_db);
    return NULL;
  }

  ret = fread(data_in, sizeof(uint8_t), byte_cnt, fp);
  fclose(fp);
  if (ret == 0) {
    fprintf(stderr, "Error in Reading from file %s\n", fname_db);
    return NULL;
  }

  /* Do AES decryption of the server db */
  AES_set_decrypt_key(aes_key, 256, &dec_key);
  AES_cbc_encrypt(data_in, data_out, byte_cnt, &dec_key, iv, AES_DECRYPT);
  data_out[byte_cnt] = '\0';

  *data_out_len = byte_cnt;
  free(data_in);

  return data_out;
}