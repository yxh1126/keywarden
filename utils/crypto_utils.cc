//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
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
    LOG(ERROR) << kClassName << MSG << "Error in accessing the private key";
    return false;
  }
  priv_key = reinterpret_cast<RSA*>(pri_key_ptr);

  /* Sign the Image Hash with Private Key */
  ret = RSA_sign(NID_sha256, img_hash, len, rsa_sign, rsa_len, priv_key);

  if (ret != 1) {
    LOG(ERROR) << kClassName << MSG << "Error in signing the hash value";
    return false;
  }
  return true;
}

bool CryptoUtils::RsaSignVerify(uint8_t* img_hash, uint32_t len,
                                uint8_t* rsa_sign, uint32_t rsa_len,
                                const char* pub_key_name, const int fmt) {
  int ret;
  FILE* fpubkey;
  RSA* pub_key;

  /* Open the private Key */
  fpubkey = fopen(pub_key_name, "r");
  if (fpubkey == NULL) {
    LOG(ERROR) << kClassName << MSG << "Error in open pubkey: " << pub_key_name;
    return false;
  }

  if (fmt == 0) {
    /* Reads the PKCS#1 format public key - e.g. NXP LX2160 */
    pub_key = PEM_read_RSAPublicKey(fpubkey, NULL, NULL, NULL);
  } else if (fmt == 1) {
    /* Reads the PEM format - e.g. Horizon J5 */
    pub_key = PEM_read_RSA_PUBKEY(fpubkey, NULL, NULL, NULL);
  } else {
    /* Do nothing and intended to let pub_key as NULL */
    pub_key = NULL;
  }

  fclose(fpubkey);
  if (pub_key == NULL) {
    LOG(ERROR) << kClassName << MSG << "Error in read pubkey: " << pub_key_name;
    return false;
  }

  /* Verify the Signature with Public Key and Hash */
  ret = RSA_verify(NID_sha256, img_hash, len, rsa_sign, rsa_len, pub_key);
  RSA_free(pub_key);

  if (ret != 1) {
    LOG(ERROR) << kClassName << MSG << "Error in signature verification";
    return false;
  }

  return true;
}

bool CryptoUtils::DumpRsaPubKey(const char* key_name, char* pub_key_pem,
                                char* pub_key_der, uint8_t* pubkey_der_hash) {
  EVP_PKEY* priv_key;
  BIO *rsa_pem_bio, *pem_buff, *der_buff;
  int ret;
  char* pub_pem_buf;
  uint8_t* pub_der_buf;
  int64_t buf_len;

  if (pub_key_pem == NULL || pub_key_der == NULL || pubkey_der_hash == NULL) {
    LOG(ERROR) << kClassName << MSG << "Public key buffer empty error";
    return false;
  }

  rsa_pem_bio = BIO_new_file(key_name, "r");
  priv_key = PEM_read_bio_PrivateKey(rsa_pem_bio, NULL, NULL, NULL);
  if (priv_key == NULL) {
    LOG(ERROR) << kClassName << MSG << "Failed to loading the private key";
    return false;
  }

  pem_buff = BIO_new(BIO_s_mem());
  ret = PEM_write_bio_PUBKEY(pem_buff, priv_key);
  if (ret != 1) {
    LOG(ERROR) << kClassName << MSG << "Failed to write PEM public key";
    return false;
  }

  der_buff = BIO_new(BIO_s_mem());
  ret = i2d_PUBKEY_bio(der_buff, priv_key);
  if (ret != 1) {
    LOG(ERROR) << kClassName << MSG << "Failed to write DER public key";
    return false;
  }

  buf_len = BIO_get_mem_data(pem_buff, &pub_pem_buf);
  if (buf_len <= 0) {
    LOG(ERROR) << kClassName << MSG << "Failed to dumping PEM public key";
    return false;
  }

  /* Copy buffer data as output */
  snprintf(pub_key_pem, strlen(pub_pem_buf) + 1, "%s", pub_pem_buf);

  buf_len = BIO_get_mem_data(der_buff, &pub_der_buf);
  if (buf_len <= 0) {
    LOG(ERROR) << kClassName << MSG << "Failed to dumping DER public key";
    return false;
  }

  /* Copy and convert buffer data as output */
  if (!FmtUtils::BytesToHexString(pub_der_buf, buf_len, pub_key_der,
                                  KEY_SIZE_BYTES)) {
    LOG(ERROR) << kClassName << MSG << "Error in DER pubkey data conversion";
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
    LOG(ERROR) << kClassName << MSG << "Error in opening file: " << key_name;
    return false;
  }

  priv_key = PEM_read_RSAPrivateKey(fpriv, NULL, NULL, NULL);
  fclose(fpriv);
  if (priv_key == NULL) {
    LOG(ERROR) << kClassName << MSG << "Error in reading file: " << key_name;
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
    LOG(ERROR) << kClassName << MSG << "Empty file or read failure: " << fpath;
    return "";
  }

  GetSha256Hash(rdtxt, hash_out);
  return FmtUtils::BytesToHexString(hash_out, SHA256_DIGEST_LENGTH);
}

std::string CryptoUtils::GetRsaPubKeyHash(const std::string& public_key,
                                          const int key_set) {
  int n_size, e_size;
  uint8_t n_data[KEY_SIZE_BYTES];
  uint8_t e_data[KEY_SIZE_BYTES];
  uint8_t hash_out[SHA256_DIGEST_LENGTH];

  PubKeyTable pub_key_tb;
  std::memset(&pub_key_tb, 0, sizeof(PubKeyTable));

  PubBigNum pbn = FmtUtils::PemPubToBigNum(public_key, key_set);
  pub_key_tb.length = strlen(pbn.n);
  if (pub_key_tb.length == 0)
    return "";

  n_size = FmtUtils::HexStringToBytes(pbn.n, n_data, KEY_SIZE_BYTES);
  e_size = FmtUtils::HexStringToBytes(pbn.e, e_data, KEY_SIZE_BYTES);
  std::memcpy(pub_key_tb.content, n_data, n_size);
  std::memcpy(pub_key_tb.content + 2 * n_size - e_size, e_data, e_size);

  GetSha256Hash(&pub_key_tb, sizeof(PubKeyTable), hash_out);
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
    LOG(ERROR) << kClassName << MSG << "Error in opening file: " << fname_db;
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
    LOG(ERROR) << kClassName << MSG << "Error in opening file: " << fname_db;
    return NULL;
  }

  ret = fread(data_in, sizeof(uint8_t), byte_cnt, fp);
  fclose(fp);
  if (ret == 0) {
    LOG(ERROR) << kClassName << MSG << "Error in reading file: " << fname_db;
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
