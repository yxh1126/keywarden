//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#ifndef UTILS_DATA_UTILS_H_
#define UTILS_DATA_UTILS_H_

#include <cstdint>
#include <string>

#include "utils/common.h"

namespace utils {
class DataUtils {
 public:
  ~DataUtils();

  bool ServerDataInit(const char* db_path);
  bool CheckDataValidity();
  std::string ServerRsaSignHash(const char* hash_str, const int key_set,
                                const int key_id);
  std::string ServerRsaGetPubkey(const int key_set, const int key_id,
                                 const int job_type);

 private:
  static constexpr const char* kClassName = "DataUtils";
  static constexpr const char* kFailureMsg = RPC_FAILURE_MSG;

  ServerKeyPair key_pair_[SUPRT_KEY_SET][SUPRT_KEY_ID];
  ServerPubkeyPack pubkey_pack_[SUPRT_KEY_SET][SUPRT_KEY_ID];

  uint64_t sign_req_cnt_ = 0;
  uint64_t pubkey_req_cnt_ = 0;
  bool is_server_init_ = false;

  void ServerPriKeyClear();
  bool FillKeyBuffer(const char* pri_key_str, const char* pub_key_str,
                     const int key_set_id, const int key_pair_id);
  bool IsPrintableStr(const char* str_in);
};
}  // namespace utils
#endif  // UTILS_DATA_UTILS_H_
