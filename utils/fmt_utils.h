//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#ifndef UTILS_FMT_UTILS_H_
#define UTILS_FMT_UTILS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "utils/common.h"

namespace utils {
class FmtUtils {
 public:
  // Data conversion
  static int HexStringToBytes(const char* hex_str, uint8_t* data_buf,
                              const size_t buf_len);
  static int HexStringToBytes(const std::string& hex_str, uint8_t* data_buf,
                              const size_t buf_len);
  static bool BytesToHexString(const uint8_t* data_buf, const size_t buf_len,
                               char* hex_str, const size_t hex_len);
  static std::string BytesToHexString(const uint8_t* data_buf,
                                      const size_t buf_len);
  static PubBigNum PemPubToBigNum(const std::string& public_key,
                                  const int key_set);

  // Standard output
  static void FmtOutAsString(const std::string& data_str);
  static void FmtOutAsBytes(const std::string& data_str);
  static void FmtOutAsSslSign(const std::string& signature,
                              const std::string& fname);
  static void FmtOutAsPubBigNum(const std::string& public_key,
                                const int key_set);

  // File read operation
  static std::string ReadText(const std::string& fpath);
  static bool ReadText(const std::string& fpath, std::vector<std::string>* t);

  static bool ReadBytes(const std::string& fpath, uint8_t* data_buf,
                        const size_t buf_len);
  static std::string ReadSha256Hash(const std::string& fpath);

  // File write operation
  static void WriteText(const std::string& fpath, const std::string& data_str);
  static void WriteBytes(const std::string& fpath, const std::string& data_str);

 private:
  static constexpr const char* kClassName = "FmtUtils";
  static constexpr const char* kFileModeWt = "w";
  static constexpr const char* kFileModeWb = "wb";
  static constexpr const char* kFileModeRb = "rb";
};
}  // namespace utils
#endif  // UTILS_FMT_UTILS_H_
