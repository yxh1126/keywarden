//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "client/common/rpc_sign_client.h"

namespace client {
namespace common {
namespace test {

class RpcSignClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    channel = grpc::CreateChannel("localhost:50051",
                                  grpc::InsecureChannelCredentials());
    client = std::make_unique<CodeSigningClient>(channel);
  }

 protected:
  std::shared_ptr<Channel> channel;
  std::unique_ptr<CodeSigningClient> client;
};

TEST_F(RpcSignClientTest, TestGetRsaSignature) {
  std::string test_hash_str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  EXPECT_NE(client->GetRsaSignature(test_hash_str, 2048, 1), "");
}

TEST_F(RpcSignClientTest, TestGetRsaPublicKey) {
  EXPECT_NE(client->GetRsaPublicKey(2048, 1, 1), "");
}

}  // namespace test
}  // namespace common
}  // namespace client
