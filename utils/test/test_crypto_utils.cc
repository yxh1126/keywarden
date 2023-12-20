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

}  // namespace test
}  // namespace utils
