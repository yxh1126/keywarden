//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "client/common/rpc_sign_client.h"
#include "utils/fmt_utils.h"
#include "utils/crypto_utils.h"

using utils::FmtUtils;
using utils::CryptoUtils;

namespace client {
namespace common {
namespace test {

class RpcSignClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    host_ip = "localhost:50051";
    channel = grpc::CreateChannel(host_ip, grpc::InsecureChannelCredentials());
    client = std::make_unique<CodeSigningClient>(channel);
    test_hash_str =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  }

 protected:
  std::string host_ip;
  std::shared_ptr<Channel> channel;
  std::unique_ptr<CodeSigningClient> client;
  std::string test_hash_str;
};

TEST_F(RpcSignClientTest, TestGetRsaSignature) {
  EXPECT_EQ(client->GetRsaSignature("bad_hash_str", 2048, 1), RPC_FAILURE_MSG);
}

TEST_F(RpcSignClientTest, TestGetRsaPublicKey) {
  EXPECT_EQ(client->GetRsaPublicKey(2048, 0, JOB_LX2160_PUB), RPC_FAILURE_MSG);
}

TEST_F(RpcSignClientTest, TestVerifySignature) {
  int key_set[] = {RSA_1024_KEY_SET, RSA_2048_KEY_SET};
  int pub_type[] = {JOB_LX2160_PUB, JOB_J5_PUB_PEM};
  std::string test_pub_name = "tmpkey";

  for (int type = 0; type < SUPRT_PUB_TYPE; type++) {
    for (int set = 0; set < SUPRT_KEY_SET; set++) {
      for (int id = 1; id < SUPRT_KEY_ID; id++) {
        std::string pub_key_pem =
          client->GetRsaPublicKey(key_set[set], id + 1, pub_type[type]);
        if (pub_key_pem == RPC_FAILURE_MSG) break;

        std::string test_sign_str =
          client->GetRsaSignature(test_hash_str, key_set[set], id + 1);
        FmtUtils::WriteText(test_pub_name, pub_key_pem);

        EXPECT_EQ(pub_key_pem, FmtUtils::ReadText(test_pub_name));
        EXPECT_TRUE(client->VerifyRsaSignature(test_hash_str, test_sign_str,
                                               test_pub_name, pub_type[type]));
      }
    }
  }
}

TEST_F(RpcSignClientTest, TestVerifyPubkeyHash) {
  int key_set[] = {RSA_1024_KEY_SET, RSA_2048_KEY_SET};
  int pub_type = JOB_J5_PUB_DER;
  std::string pub_key_fpt;
  std::vector<std::string> hash_list;
  int idx = 0;

  EXPECT_TRUE(FmtUtils::ReadText("data/hashlist.txt", &hash_list));
  EXPECT_EQ(hash_list.size(), 14);

  for (int set = 0; set < SUPRT_KEY_SET; set++) {
    for (int id = 1; id < SUPRT_KEY_ID; id++) {
      std::string pub_key_der =
        client->GetRsaPublicKey(key_set[set], id + 1, pub_type);
      if (pub_key_der == RPC_FAILURE_MSG) break;

      pub_key_fpt = CryptoUtils::GetRsaPubKeyHash(pub_key_der, key_set[set]);
      EXPECT_EQ(pub_key_fpt, hash_list[idx]);
      idx++;
    }
  }
}

}  // namespace test
}  // namespace common
}  // namespace client
