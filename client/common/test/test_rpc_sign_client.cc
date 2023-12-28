//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "client/common/rpc_sign_client.h"
#include "utils/fmt_utils.h"

using utils::FmtUtils;

namespace client {
namespace common {
namespace test {

class RpcSignClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hash_str1 =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    test_hash_str2 =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    channel = grpc::CreateChannel("localhost:50051",
                                  grpc::InsecureChannelCredentials());
    client = std::make_unique<CodeSigningClient>(channel);
  }

 protected:
  std::string test_hash_str1;
  std::string test_hash_str2;
  std::shared_ptr<Channel> channel;
  std::unique_ptr<CodeSigningClient> client;
};

TEST_F(RpcSignClientTest, TestGetRsaSignature) {
  EXPECT_NE(client->GetRsaSignature(test_hash_str1, 2048, 1), "");
}

TEST_F(RpcSignClientTest, TestGetRsaPublicKey) {
  EXPECT_NE(client->GetRsaPublicKey(2048, 1, 1), "");
}

TEST_F(RpcSignClientTest, TestVerifySignature) {
  int key_set[] = {1024, 2048};
  int pem_type_pub = 1;
  std::string test_pub_name = "tmp";

  for (int set = 0; set < SUPRT_KEY_SET; set++) {
    for (int id = 0; id < SUPRT_KEY_ID; id++) {
      std::string pub_key_pem =
        client->GetRsaPublicKey(key_set[set], id + 1, pem_type_pub);
      std::string test_sign_str =
        client->GetRsaSignature(test_hash_str2, key_set[set], id + 1);
      FmtUtils::WriteText(test_pub_name, pub_key_pem);
      EXPECT_EQ(pub_key_pem, FmtUtils::ReadText(test_pub_name));
      bool res = client->VerifyRsaSignature(test_hash_str2, test_sign_str,
                                            test_pub_name);
      EXPECT_FALSE(res);
    }
  }
}

}  // namespace test
}  // namespace common
}  // namespace client
