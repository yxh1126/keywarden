//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#include "utils/data_utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "utils/crypto_utils.h"
#include "utils/fmt_utils.h"
#include "json-c/json.h"

using utils::DataUtils;
using utils::CryptoUtils;
using utils::FmtUtils;

DataUtils::~DataUtils() {
  ServerPriKeyClear();
}

bool DataUtils::ServerDataInit(const char* db_path) {
  int data_out_len = 0, cnt = 0;
  int idx, key_pair_size, key_set_id;
  bool ret;
  uint8_t* server_db;
  const char *key_str, *pub_str, *pri_str;
  json_object *server_db_jobj, *key_pair;

  if (is_server_init_) {
    LOG(ERROR) << kClassName << MSG << "Server data already initialized";
    return false;
  }

  /* Decrypt the sever db data bundle */
  server_db = CryptoUtils::Aes256Decrypt(db_path, &data_out_len);
  if (server_db == NULL)
    return false;

  /* Parse the decrypted json string to a parser */
  server_db_jobj = json_tokener_parse(reinterpret_cast<char*>(server_db));
  if (server_db_jobj == NULL) {
    LOG(ERROR) << kClassName << MSG << "Failed to parse server database";
    return false;
  }

  /* Parse the JSON object to key piars and loading into memory */
  json_object_object_foreach(server_db_jobj, key, val) {
    cnt++;
    if (cnt > 2) {
      LOG(ERROR) << kClassName << MSG << "Sever db contains error sets of data";
      return false;
    }

    if (strcmp(key, "l1024") == 0) {
      key_set_id = LEN_1024_KEY_SET;
    } else if (strcmp(key, "l2048") == 0) {
      key_set_id = LEN_2048_KEY_SET;
    } else {
      LOG(ERROR) << kClassName << MSG << "Bad entry data in server db JSON key";
      return false;
    }

    key_pair_size = json_object_array_length(val);
    for (idx = 0; idx < key_pair_size; idx++) {
      key_str = json_object_get_string(json_object_array_get_idx(val, idx));
      key_pair = json_tokener_parse(key_str);
      pri_str = json_object_get_string(json_object_array_get_idx(key_pair, 0));
      pub_str = json_object_get_string(json_object_array_get_idx(key_pair, 1));

      ret = FillKeyBuffer(pri_str, pub_str, key_set_id, idx);
      json_object_put(key_pair);
      if (!ret) {
        LOG(ERROR) << kClassName << MSG << "Failed to fill data to key buffer";
        return false;
      }
    }
  }

  json_object_put(server_db_jobj);
  free(server_db);

  if (!CheckDataValidity()) {
    LOG(ERROR) << kClassName << MSG << "Unprintable character in server db";
    return false;
  }

  is_server_init_ = true;
  return true;
}

bool DataUtils::CheckDataValidity() {
  char *target1, *target2, *target3, *target4;
  int key_set, key_id;

  for (key_set = 0; key_set < SUPRT_KEY_SET; key_set++) {
    for (key_id = 0; key_id < SUPRT_KEY_ID; key_id++) {
      target1 = (key_pair_[key_set][key_id]).pub_key;
      target2 = (pubkey_pack_[key_set][key_id]).pub_key_pem;
      target3 = (pubkey_pack_[key_set][key_id]).pub_key_der;
      target4 = (pubkey_pack_[key_set][key_id]).pub_key_der_sign;

      if (!IsPrintableStr(target1) || !IsPrintableStr(target2) ||
          !IsPrintableStr(target3) || !IsPrintableStr(target4)) {
        return false;
      }
    }
  }
  return true;
}

bool DataUtils::FillKeyBuffer(const char* pri_key_str, const char* pub_key_str,
                              const int key_set_id, const int key_pair_id) {
  const char* tmp_key_file = "tmp.db";
  char *pubkey_pem_j5, *pubkey_der_j5, *pubkey_der_sig_j5;
  uint32_t pubkey_der_sig_len;
  uint8_t pubkey_der_hash[SHA256_DIGEST_LENGTH];
  uint8_t pubkey_der_sig[KEY_SIZE_BYTES];

  FILE* ftmpkey;
  void* pri_key_ptr;
  int ret;

  if (pri_key_str == NULL || pub_key_str == NULL)
    return false;

  if (key_set_id != LEN_1024_KEY_SET && key_set_id != LEN_2048_KEY_SET)
    return false;

  if (key_pair_id < 0 || key_pair_id >= SUPRT_KEY_ID)
    return false;

  ftmpkey = fopen(tmp_key_file, "w");
  if (ftmpkey == NULL) {
    LOG(ERROR) << kClassName << MSG << "Error in file open: " << tmp_key_file;
    return false;
  }

  ret = fputs(pri_key_str, ftmpkey);
  fclose(ftmpkey);
  if (ret < 0) {
    LOG(ERROR) << kClassName << MSG << "Error in file write: " << tmp_key_file;
    return false;
  }

  /* Fill buffer for original private key and public key */
  if (!CryptoUtils::ExtractRsaPriKey(tmp_key_file, &pri_key_ptr))
    return false;

  (key_pair_[key_set_id][key_pair_id]).pri_key = pri_key_ptr;
  snprintf((key_pair_[key_set_id][key_pair_id]).pub_key,
           strlen(pub_key_str) + 1, "%s", pub_key_str);

  /* Fill buffer for extended public key type */
  pubkey_pem_j5 = (pubkey_pack_[key_set_id][key_pair_id]).pub_key_pem;
  pubkey_der_j5 = (pubkey_pack_[key_set_id][key_pair_id]).pub_key_der;
  pubkey_der_sig_j5 = (pubkey_pack_[key_set_id][key_pair_id]).pub_key_der_sign;

  if (!CryptoUtils::DumpRsaPubKey(tmp_key_file, pubkey_pem_j5, pubkey_der_j5,
          pubkey_der_hash))
    return false;

  /* Sign the DER format public key hash with the private key */
  if (!CryptoUtils::RsaSignHash(pubkey_der_hash, SHA256_DIGEST_LENGTH,
                                pubkey_der_sig, &pubkey_der_sig_len,
                                pri_key_ptr)) {
    LOG(ERROR) << kClassName << MSG << "Error in signing DER public key";
    return false;
  }

  /* Fill buffer for the signed public key */
  if (!FmtUtils::BytesToHexString(pubkey_der_sig, pubkey_der_sig_len,
                                  pubkey_der_sig_j5, KEY_SIZE_BYTES)) {
    LOG(ERROR) << kClassName << MSG << "Error in signed pubkey data conversion";
    return false;
  }

  if (remove(tmp_key_file) != 0)
    return false;

  return true;
}

void DataUtils::ServerPriKeyClear() {
  void* pri_key_ptr;
  int key_set, key_id;

  for (key_set = 0; key_set < SUPRT_KEY_SET; key_set++) {
    for (key_id = 0; key_id < SUPRT_KEY_ID; key_id++) {
      pri_key_ptr = (key_pair_[key_set][key_id]).pri_key;
      if (pri_key_ptr != NULL)
        CryptoUtils::RsaPriKeyFree(pri_key_ptr);
    }
  }
}

std::string
DataUtils::ServerRsaSignHash(const char* hash_str, const int key_set,
                             const int key_id) {
  int img_hash_size, key_set_id;
  uint32_t sig_len;
  void* sign_pri_key_ptr;
  std::string sign_res;

  uint8_t img_hash[SHA256_DIGEST_LENGTH];
  uint8_t rsa_sign[KEY_SIZE_BYTES];

  /* Check received hash message from client */
  if (key_set == RSA_1024_KEY_SET) {
    key_set_id = LEN_1024_KEY_SET;
  } else if (key_set == RSA_2048_KEY_SET) {
    key_set_id = LEN_2048_KEY_SET;
  } else {
    LOG(ERROR) << kClassName << MSG << "Error in key set number from input";
    return kFailureMsg;
  }

  if (key_id < 1 || key_id > 8) {
    LOG(ERROR) << kClassName << MSG << "Error in key ID number from input";
    return kFailureMsg;
  }

  if (strlen(hash_str) != SHA256_DIGEST_LENGTH * 2) {
    LOG(ERROR) << kClassName << MSG << "Error in hash string length from input";
    return kFailureMsg;
  }

  sign_pri_key_ptr = (key_pair_[key_set_id][key_id - 1]).pri_key;
  if (sign_pri_key_ptr == NULL) {
    LOG(ERROR) << kClassName << MSG << "Error in access private key at server";
    return kFailureMsg;
  }

  /* Convert the received hex string to int before sign */
  img_hash_size = FmtUtils::HexStringToBytes(hash_str, img_hash,
      SHA256_DIGEST_LENGTH);
  if (img_hash_size != SHA256_DIGEST_LENGTH) {
    LOG(ERROR) << kClassName << MSG << "Error in hash data conversion";
    return kFailureMsg;
  }

  /* Call the CST sign API to get signature */
  if (!CryptoUtils::RsaSignHash(img_hash, SHA256_DIGEST_LENGTH, rsa_sign,
                                &sig_len, sign_pri_key_ptr)) {
    LOG(ERROR) << kClassName << MSG << "Error in sign the hash data at server";
    return kFailureMsg;
  }

  if (sig_len * 2 >= KEY_SIZE_BYTES) {
    LOG(ERROR) << kClassName << MSG << "Error in signature buffer size";
    return kFailureMsg;
  }

  /* Print out sign info */
  sign_req_cnt_++;
  printf("[%lu] ", sign_req_cnt_);
  printf("hash:%s hash_len:%ld", hash_str, strlen(hash_str) / 2);
  printf(" sig_len:%d key_id:%d key_set:%d\n", sig_len, key_id, key_set);

  /* Convert the int in the signature buffer to hex string */
  sign_res = FmtUtils::BytesToHexString(rsa_sign, sig_len);
  if (sign_res.empty()) {
    LOG(ERROR) << kClassName << MSG << "Error in signature data conversion";
    return kFailureMsg;
  }

  return sign_res;
}

std::string
DataUtils::ServerRsaGetPubkey(const int key_set, const int key_id,
                              const int job_type) {
  int key_set_id;
  char* pubkey_hex_str;

  /* Construct the public key path with the given key ID */
  if (key_set == RSA_1024_KEY_SET) {
    key_set_id = LEN_1024_KEY_SET;
  } else if (key_set == RSA_2048_KEY_SET) {
    key_set_id = LEN_2048_KEY_SET;
  } else {
    LOG(ERROR) << kClassName << MSG << "Error in key set number from input";
    return kFailureMsg;
  }

  if (key_id < 1 || key_id > 8) {
    LOG(ERROR) << kClassName << MSG << "Error in key ID number from input";
    return kFailureMsg;
  }

  switch (job_type) {
    case JOB_LX2160_PUB:
      pubkey_hex_str = (key_pair_[key_set_id][key_id - 1]).pub_key;
      break;

    case JOB_J5_PUB_PEM:
      pubkey_hex_str = (pubkey_pack_[key_set_id][key_id - 1]).pub_key_pem;
      break;

    case JOB_J5_PUB_DER:
      pubkey_hex_str = (pubkey_pack_[key_set_id][key_id - 1]).pub_key_der;
      break;

    case JOB_J5_PUB_SIG:
      pubkey_hex_str = (pubkey_pack_[key_set_id][key_id - 1]).pub_key_der_sign;
      break;

    default:
      LOG(ERROR) << kClassName << MSG << "Error in job type value from input";
      return kFailureMsg;
  }

  if (strlen(pubkey_hex_str) < PUB_KEY_STRLEN_THLD) {
    LOG(ERROR) << kClassName << MSG << "Error in access public key at server";
    return kFailureMsg;
  }

  pubkey_req_cnt_++;
  LOG(INFO) << kClassName << ": " << pubkey_req_cnt_;

  return std::string(pubkey_hex_str);
}

bool DataUtils::IsPrintableStr(const char* str_in) {
  int idx = 0;
  while (str_in[idx] != '\0') {
    if (!isprint(static_cast<uint8_t>(str_in[idx])) && str_in[idx] != '\n')
      return false;
    idx++;
  }
  return true;
}
