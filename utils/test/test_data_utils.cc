//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "utils/common.h"
#include "utils/data_utils.h"

namespace utils {
namespace test {

class DataUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    file_path = "data/server.db";
    key_obj = std::make_unique<DataUtils>();
  }

 protected:
  std::string file_path;
  std::unique_ptr<DataUtils> key_obj;
};

TEST_F(DataUtilsTest, TestServerDataInit) {
  EXPECT_TRUE(key_obj->ServerDataInit(file_path.c_str()));
  EXPECT_FALSE(key_obj->ServerDataInit(file_path.c_str()));
  EXPECT_FALSE(key_obj->ServerDataInit(file_path.c_str()));
}

TEST_F(DataUtilsTest, TestDataValidity) {
  EXPECT_TRUE(key_obj->ServerDataInit(file_path.c_str()));
  EXPECT_TRUE(key_obj->CheckDataValidity());
}

}  // namespace test
}  // namespace utils
