//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#ifndef UTILS_CRYPTO_UTILS_H_
#define UTILS_CRYPTO_UTILS_H_

#include <cstdint>
#include <string>

namespace utils {
class CryptoUtils {
 public:
  // RSA algorithm support
  static bool RsaSignHash(uint8_t* img_hash, uint32_t len, uint8_t* rsa_sign,
                          uint32_t* rsa_len, void* pri_key_ptr);
  static bool RsaSignVerify(uint8_t* img_hash, uint32_t len, uint8_t* rsa_sign,
                            uint32_t rsa_len, const char* pub_key_name);
  static bool DumpRsaPubKey(const char* key_name, char* pub_key_pem,
                            char* pub_key_der, uint8_t* pubkey_der_hash);
  static bool ExtractRsaPriKey(const char* key_name, void** pri_key_ptr);
  static void RsaPriKeyFree(void* pri_key_ptr);

  // Hash algorithm support
  static void GetSha256Hash(const void* data, uint32_t len, uint8_t* hash);
  static void GetSha256Hash(const std::string& data, uint8_t* hash);
  static std::string GetFileSha256Hash(const std::string& fpath);

  // AES algorithm support
  static uint8_t* Aes256Encrypt(const uint8_t* data_in, const int data_len,
                                const uint8_t* aes_key, int* data_out_len);
  static uint8_t* Aes256Decrypt(const char* fname_db, int* data_out_len);

 private:
  static constexpr const char* kClassName = "CryptoUtils";
  static constexpr const uint32_t kBufferSize = 16 * 1024;
};
}  // namespace utils
#endif  // UTILS_CRYPTO_UTILS_H_
