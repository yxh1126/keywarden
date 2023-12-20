//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#ifndef SERVER_RPC_SIGN_SERVER_H_
#define SERVER_RPC_SIGN_SERVER_H_

#include <string>
#include <memory>

#include "utils/data_utils.h"
#include "grpcpp/grpcpp.h"
#include "protos/signserver.grpc.pb.h"

using grpc::ServerContext;
using grpc::Status;
using signserver::CodeSigning;
using signserver::RsaSignRequest;
using signserver::RsaSignReply;
using signserver::RsaPubkeyRequest;
using signserver::RsaPubkeyReply;
using utils::DataUtils;

namespace server {
class CodeSigningService final : public CodeSigning::Service {
 public:
  explicit CodeSigningService(const std::string& key_db);

  Status GetRsaSignature(ServerContext* context,
                         const RsaSignRequest* request,
                         RsaSignReply* reply) override;
  Status GetRsaPublicKey(ServerContext* context,
                         const RsaPubkeyRequest* request,
                         RsaPubkeyReply* reply) override;
  bool GetServerStatus();

 private:
  static constexpr const char* kClassName = "CodeSigningService";

  std::unique_ptr<DataUtils> key_obj_;
  bool is_server_ready_;
};
}  // namespace server
#endif  // SERVER_RPC_SIGN_SERVER_H_
