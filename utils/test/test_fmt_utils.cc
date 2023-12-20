//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "utils/common.h"
#include "utils/fmt_utils.h"

namespace utils {
namespace test {

#define TEST_FILE_NAME "tmp"
#define TEST_HEX_STR "123456abcdef"
#define TEST_HEX_LEN 12

class FmtUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    bin_path = "data/hexdata.bin";
    txt_path = "data/hexdata.txt";
  }

 protected:
  std::string bin_path;
  std::string txt_path;
};

TEST_F(FmtUtilsTest, TestHexStringConv) {
  uint8_t hex_dat[SHA256_DIGEST_LENGTH / 2];
  uint8_t hex_cmp[SHA256_DIGEST_LENGTH];

  std::string hex_str = FmtUtils::ReadText(txt_path);
  EXPECT_TRUE(FmtUtils::ReadBytes(bin_path, hex_dat, SHA256_DIGEST_LENGTH / 2));
  int hex_size =
    FmtUtils::HexStringToBytes(hex_str, hex_cmp, SHA256_DIGEST_LENGTH);

  std::string conv_hex_a = FmtUtils::BytesToHexString(hex_dat, 10);
  std::string conv_hex_b = FmtUtils::BytesToHexString(hex_cmp, 10);
  std::string conv_hex_c = FmtUtils::BytesToHexString(hex_cmp, hex_size);

  EXPECT_LT(hex_size, SHA256_DIGEST_LENGTH);
  EXPECT_EQ(conv_hex_a, conv_hex_b);
  EXPECT_NE(conv_hex_a, conv_hex_c);
  EXPECT_EQ(hex_str, conv_hex_c);
}

TEST_F(FmtUtilsTest, TestWriteText) {
  std::string tmp = TEST_HEX_STR;
  FmtUtils::WriteText(TEST_FILE_NAME, tmp);
  EXPECT_EQ(tmp, FmtUtils::ReadText(TEST_FILE_NAME));
}

TEST_F(FmtUtilsTest, TestWriteBytes) {
  uint8_t hex_dat[TEST_HEX_LEN / 2];
  std::string tmp = TEST_HEX_STR;
  FmtUtils::WriteBytes(TEST_FILE_NAME, tmp);
  EXPECT_TRUE(FmtUtils::ReadBytes(TEST_FILE_NAME, hex_dat, TEST_HEX_LEN / 2));

  EXPECT_NE(tmp, FmtUtils::ReadText(TEST_FILE_NAME));
  EXPECT_EQ(tmp, FmtUtils::BytesToHexString(hex_dat, TEST_HEX_LEN / 2));
}

TEST_F(FmtUtilsTest, TestPemPubToBigNum) {
  std::string pem_pub =
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aab8801"
    "ae63510401d453ee433a9c7d560f005f127e3b0d9ac2224b4eb8971115593959f4198bd21"
    "653b43350b017ffaf9f03f6a2fc96e177cb97a6ace94cec92321eca7ed253903d98455c4f"
    "e1523092c64a19eaa672c8b2dc4a5dc10ca12fdd7c0af60a33b5ef8bc15305cfd0970ca64"
    "30098e35d3439e8b389b594a14d5576b0ee6d9d73ddc3b4984502110588f3275a6bbd1c45"
    "90569e22188b0403b2bf0080ba8c6a6addb6e769d96ddda9f07c3bc2b9ca63c06f4834703"
    "181a2d45cf87c04a34d3af5eeb8f99d56829483835b6ce8eb0b32aa3cfb43c8644f1a2d05"
    "8245bb5be285241d65912f7bf14711d23316c3340e67689d91cf0321bcbfc33e27d020301"
    "0001";
  std::string n =
    "aab8801ae63510401d453ee433a9c7d560f005f127e3b0d9ac2224b4eb8971115593959f4"
    "198bd21653b43350b017ffaf9f03f6a2fc96e177cb97a6ace94cec92321eca7ed253903d9"
    "8455c4fe1523092c64a19eaa672c8b2dc4a5dc10ca12fdd7c0af60a33b5ef8bc15305cfd0"
    "970ca6430098e35d3439e8b389b594a14d5576b0ee6d9d73ddc3b4984502110588f3275a6"
    "bbd1c4590569e22188b0403b2bf0080ba8c6a6addb6e769d96ddda9f07c3bc2b9ca63c06f"
    "4834703181a2d45cf87c04a34d3af5eeb8f99d56829483835b6ce8eb0b32aa3cfb43c8644"
    "f1a2d058245bb5be285241d65912f7bf14711d23316c3340e67689d91cf0321bcbfc33e27"
    "d";
  std::string e = "010001";

  PubBigNum bn = FmtUtils::PemPubToBigNum(pem_pub, RSA_2048_KEY_SET);
  EXPECT_EQ(std::string(bn.n), n);
  EXPECT_EQ(std::string(bn.e), e);

  bn = FmtUtils::PemPubToBigNum(pem_pub, RSA_1024_KEY_SET);
  EXPECT_NE(std::string(bn.n), n);
  EXPECT_EQ(std::string(bn.e), e);

  bn = FmtUtils::PemPubToBigNum(pem_pub, 123);
  EXPECT_EQ(std::string(bn.n), "");
  EXPECT_EQ(std::string(bn.e), "");
}

}  // namespace test
}  // namespace utils
