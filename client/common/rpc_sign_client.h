//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#ifndef CLIENT_COMMON_RPC_SIGN_CLIENT_H_
#define CLIENT_COMMON_RPC_SIGN_CLIENT_H_

#include <memory>
#include <string>

#include "utils/common.h"
#include "grpcpp/grpcpp.h"
#include "protos/signserver.grpc.pb.h"

using grpc::Channel;
using signserver::CodeSigning;

namespace client {
namespace common {
class CodeSigningClient {
 public:
  explicit CodeSigningClient(std::shared_ptr<Channel> channel);

  std::string GetRsaSignature(const std::string& hash_str, const int key_set,
                              const int key_id);
  std::string GetRsaPublicKey(const int key_set, const int key_id,
                              const int key_type);
  void FmtRsaSignature(const std::string& hash_str, const int key_set,
                       const int key_id, const char fmt = FMT_RSA_SIGN_STR,
                       const std::string& fname = "",
                       const std::string& tofile = "");
  void FmtRsaPublicKey(const int key_set, const int key_id,
                       const int key_type, const char fmt = FMT_RSA_PUB_STR,
                       const std::string& tofile = "");
  static bool SigRequestCheck(const std::string& hash_str, const int key_set,
                              const int key_id, const char fmt,
                              const std::string& fname);
  static bool PubRequestCheck(const int key_set, const int key_id,
                              const int key_type, const char fmt);
 private:
  static constexpr const char* kClassName = "CodeSigningClient";

  std::unique_ptr<CodeSigning::Stub> stub_;
};
}  // namespace common
}  // namespace client
#endif  // CLIENT_COMMON_RPC_SIGN_CLIENT_H_
