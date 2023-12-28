//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "client/common/rpc_sign_client.h"

#include <cstdio>
#include <iostream>

#include "utils/crypto_utils.h"
#include "utils/fmt_utils.h"

using grpc::ClientContext;
using grpc::Status;
using signserver::RsaSignRequest;
using signserver::RsaSignReply;
using signserver::RsaPubkeyRequest;
using signserver::RsaPubkeyReply;
using utils::CryptoUtils;
using utils::FmtUtils;
using client::common::CodeSigningClient;

CodeSigningClient::CodeSigningClient(std::shared_ptr<Channel> channel)
      : stub_(CodeSigning::NewStub(channel)) {}

std::string
CodeSigningClient::GetRsaSignature(const std::string& hash_str,
                                   const int key_set, const int key_id) {
  // Data we are sending to the server.
  RsaSignRequest request;
  request.set_hash_str(hash_str);
  request.set_key_set(key_set);
  request.set_key_id(key_id);

  // Container for the data we expect from the server.
  RsaSignReply reply;

  // Context for the client. It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors.
  ClientContext context;

  // The actual RPC.
  Status status = stub_->GetRsaSignature(&context, request, &reply);

  // Act upon its status.
  if (status.ok()) {
    return reply.signature();
  } else {
    std::cout << status.error_code() << ": " << status.error_message()
              << std::endl;
    return RPC_FAILURE_MSG;
  }
}

std::string
CodeSigningClient::GetRsaPublicKey(const int key_set, const int key_id,
                                   const int key_type) {
  // Data we are sending to the server.
  RsaPubkeyRequest request;
  request.set_key_set(key_set);
  request.set_key_id(key_id);
  request.set_key_type(key_type);

  // Container for the data we expect from the server.
  RsaPubkeyReply reply;

  // Context for the client. It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors.
  ClientContext context;

  // The actual RPC.
  Status status = stub_->GetRsaPublicKey(&context, request, &reply);

  // Act upon its status.
  if (status.ok()) {
    return reply.public_key();
  } else {
    std::cout << status.error_code() << ": " << status.error_message()
              << std::endl;
    return RPC_FAILURE_MSG;
  }
}

bool CodeSigningClient::VerifyRsaSignature(const std::string& hash_str,
                                           const std::string& sign_str,
                                           const std::string& pub_key_name) {
  int hash_len, rsa_sign_len;
  uint8_t hash_data[SHA256_DIGEST_LENGTH];
  uint8_t sign_data[KEY_SIZE_BYTES];

  hash_len =
      FmtUtils::HexStringToBytes(hash_str, hash_data, SHA256_DIGEST_LENGTH);
  rsa_sign_len =
      FmtUtils::HexStringToBytes(sign_str, sign_data, KEY_SIZE_BYTES);

  return CryptoUtils::RsaSignVerify(hash_data, hash_len,
                                    sign_data, rsa_sign_len,
                                    pub_key_name.c_str());
}

void CodeSigningClient::FmtRsaSignature(const std::string& hash_str,
                                        const int key_set, const int key_id,
                                        const char fmt,
                                        const std::string& fname,
                                        const std::string& tofile) {
  std::string signature = GetRsaSignature(hash_str, key_set, key_id);

  if (signature == RPC_FAILURE_MSG)
    return;

  switch (fmt) {
    case FMT_RSA_SIGN_STR:
      if (!tofile.empty())
        FmtUtils::WriteText(tofile, signature);
      else
        FmtUtils::FmtOutAsString(signature);
      break;

    case FMT_RSA_SIGN_BYT:
      if (!tofile.empty())
        FmtUtils::WriteBytes(tofile, signature);
      else
        FmtUtils::FmtOutAsBytes(signature);
      break;

    case FMT_RSA_SIGN_SSL:
      FmtUtils::FmtOutAsSslSign(signature, fname);
      if (!tofile.empty())
        std::cout << "Not support file saving for this fmt ..." << std::endl;
      break;

    default:
      break;
  }
}

void CodeSigningClient::FmtRsaPublicKey(const int key_set, const int key_id,
                                        const int key_type, const char fmt,
                                        const std::string& tofile) {
  std::string public_key = GetRsaPublicKey(key_set, key_id, key_type);

  if (public_key == RPC_FAILURE_MSG)
    return;

  switch (fmt) {
    case FMT_RSA_PUB_STR:
      if (!tofile.empty())
        FmtUtils::WriteText(tofile, public_key);
      else
        FmtUtils::FmtOutAsString(public_key);
      break;

    case FMT_RSA_PUB_BYT:
      if (!tofile.empty())
        FmtUtils::WriteBytes(tofile, public_key);
      else
        FmtUtils::FmtOutAsBytes(public_key);
      break;

    case FMT_RSA_PUB_NUM:
      FmtUtils::FmtOutAsPubBigNum(public_key, key_set);
      if (!tofile.empty())
        std::cout << "Not support file saving for this fmt ..." << std::endl;
      break;

    default:
      break;
  }
}

bool CodeSigningClient::SigRequestCheck(const std::string& hash_str,
                                        const int key_set, const int key_id,
                                        const char fmt,
                                        const std::string& fname) {
  if (key_set != RSA_1024_KEY_SET && key_set != RSA_2048_KEY_SET)
    return false;

  if (key_id < 1 || key_id > 8)
    return false;

  if (hash_str.length() != SHA256_DIGEST_LENGTH * 2)
    return false;

  for (size_t idx = 0; idx < hash_str.length(); idx++) {
    if (!isxdigit(hash_str.at(idx)))
      return false;
  }

  switch (fmt) {
    case FMT_RSA_SIGN_STR:
      break;

    case FMT_RSA_SIGN_BYT:
      break;

    case FMT_RSA_SIGN_SSL:
      if (fname.empty()) {
        std::cout << "The name of the original file is required." << std::endl;
        return false;
      }
      break;

    default:
      return false;
  }
  return true;
}

bool CodeSigningClient::PubRequestCheck(const int key_set, const int key_id,
                                        const int key_type, const char fmt) {
  if (key_set != RSA_1024_KEY_SET && key_set != RSA_2048_KEY_SET)
    return false;

  if (key_id < 1 || key_id > 8)
    return false;

  if (key_type != JOB_LX2160_PUB && key_type != JOB_J5_PUB_PEM &&
      key_type != JOB_J5_PUB_DER && key_type != JOB_J5_PUB_SIG)
    return false;

  switch (fmt) {
    case FMT_RSA_PUB_STR:
      break;

    case FMT_RSA_PUB_BYT:
      if (key_type != JOB_J5_PUB_DER && key_type != JOB_J5_PUB_SIG)
        return false;
      break;

    case FMT_RSA_PUB_NUM:
      if (key_type != JOB_J5_PUB_DER)
        return false;
      break;

    default:
      return false;
  }
  return true;
}
