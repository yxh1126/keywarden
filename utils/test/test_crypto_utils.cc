//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "utils/common.h"
#include "utils/fmt_utils.h"
#include "utils/crypto_utils.h"

namespace utils {
namespace test {

class CryptoUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    file_path = "data/server.db";
    text_path = "data/server.txt";
    data_out_len = 0;
  }

 protected:
  std::string file_path;
  std::string text_path;
  int data_out_len;
};

TEST_F(CryptoUtilsTest, TestAes256Decrypt) {
  uint8_t* file_data_ptr;
  file_data_ptr = CryptoUtils::Aes256Decrypt(file_path.c_str(), &data_out_len);
  std::string file_str(reinterpret_cast<char*>(file_data_ptr));
  std::string cmp_str = FmtUtils::ReadText(text_path);

  EXPECT_EQ(data_out_len, 26576);
  EXPECT_EQ(file_str.substr(0, cmp_str.length()), cmp_str);

  free(file_data_ptr);
}

TEST_F(CryptoUtilsTest, TestGetSha256Hash) {
  std::string data_in = "foobar";
  std::string digest =
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
  uint8_t hash_out[SHA256_DIGEST_LENGTH];

  CryptoUtils::GetSha256Hash(data_in.c_str(), data_in.length(), hash_out);
  EXPECT_EQ(digest, FmtUtils::BytesToHexString(hash_out, SHA256_DIGEST_LENGTH));

  CryptoUtils::GetSha256Hash(data_in, hash_out);
  EXPECT_EQ(digest, FmtUtils::BytesToHexString(hash_out, SHA256_DIGEST_LENGTH));

  digest = "ecf701f727d9e2d77c4aa49ac6fbbcc997278aca010bddeeb961c10cf54d435a";
  std::string hash_str = CryptoUtils::GetFileSha256Hash("data/textfile.txt");
  EXPECT_EQ(digest, hash_str);
}

TEST_F(CryptoUtilsTest, TestGetRsaPubKeyHash) {
  std::string pem_pub =
    "30819f300d06092a864886f70d010101050003818d0030818902818100bf0c7c7632c1d53"
    "a46d08dcf6f3cbe85efdc9abd7813c8cc407f844fa114bbca28cb51c55d9679ab6fbf8a69"
    "f5eee5c78b67c8ae059ebbb4193db6fa11b4dbc8d8d5975f28cac83af289e03eeac667dc6"
    "ae64421cc7343108aa189573826fc64f0095423eb3c9ffa400be4559e0d37d0d2ab475eb8"
    "c9252ddf16f49fd279e79b0203010001";
  std::string pub_fpt =
    "9db2169937c26b9951ed5488ba97cdfa9709cf43e2b100b2a91bf8e613bf768e";

  EXPECT_EQ(CryptoUtils::GetRsaPubKeyHash(pem_pub, RSA_1024_KEY_SET), pub_fpt);

  pem_pub =
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aab8801"
    "ae63510401d453ee433a9c7d560f005f127e3b0d9ac2224b4eb8971115593959f4198bd21"
    "653b43350b017ffaf9f03f6a2fc96e177cb97a6ace94cec92321eca7ed253903d98455c4f"
    "e1523092c64a19eaa672c8b2dc4a5dc10ca12fdd7c0af60a33b5ef8bc15305cfd0970ca64"
    "30098e35d3439e8b389b594a14d5576b0ee6d9d73ddc3b4984502110588f3275a6bbd1c45"
    "90569e22188b0403b2bf0080ba8c6a6addb6e769d96ddda9f07c3bc2b9ca63c06f4834703"
    "181a2d45cf87c04a34d3af5eeb8f99d56829483835b6ce8eb0b32aa3cfb43c8644f1a2d05"
    "8245bb5be285241d65912f7bf14711d23316c3340e67689d91cf0321bcbfc33e27d020301"
    "0001";
  pub_fpt = "4a2cdacc6b297e38a5955c902c922f8d5eab8e2b9d91e66574c2cb32eb8ecfab";

  EXPECT_EQ(CryptoUtils::GetRsaPubKeyHash(pem_pub, RSA_2048_KEY_SET), pub_fpt);
}

}  // namespace test
}  // namespace utils
