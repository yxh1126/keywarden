//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#include "server/rpc_sign_server.h"

#include <iostream>
#include <memory>
#include <string>

using server::CodeSigningService;

CodeSigningService::CodeSigningService(const std::string& key_db) {
  is_server_ready_ = false;
  key_obj_ = std::make_unique<DataUtils>();
  if (key_obj_->ServerDataInit(key_db.c_str()))
    is_server_ready_ = true;
}

Status CodeSigningService::GetRsaSignature(ServerContext* context,
                                           const RsaSignRequest* request,
                                           RsaSignReply* reply) {
  std::string rsa_sig_str =
    key_obj_->ServerRsaSignHash(request->hash_str().c_str(),
                                request->key_set(),
                                request->key_id());
  reply->set_signature(rsa_sig_str);
  return Status::OK;
}

Status CodeSigningService::GetRsaPublicKey(ServerContext* context,
                                           const RsaPubkeyRequest* request,
                                           RsaPubkeyReply* reply) {
  std::string rsa_pubkey_str =
    key_obj_->ServerRsaGetPubkey(request->key_set(),
                                 request->key_id(),
                                 request->key_type());
  reply->set_public_key(rsa_pubkey_str);
  return Status::OK;
}

bool CodeSigningService::GetServerStatus() {
  return is_server_ready_;
}
