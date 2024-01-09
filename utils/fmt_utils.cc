//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#include "utils/fmt_utils.h"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <streambuf>
#include <memory>

using utils::FmtUtils;

int FmtUtils::HexStringToBytes(const char* hex_str, uint8_t* data_buf,
                               const size_t buf_len) {
  int idx = 0, num;
  int data_size = -1;
  size_t hex_str_len;
  char hex_buf[3];

  if (hex_str == NULL || data_buf == NULL)
    return data_size;

  hex_str_len = strlen(hex_str);
  if (hex_str_len == 0 || hex_str_len % 2 != 0 || hex_str_len / 2 > buf_len)
    return data_size;

  hex_buf[2] = '\0';
  while (hex_str[idx] != '\0') {
    hex_buf[0] = hex_str[idx];
    hex_buf[1] = hex_str[idx + 1];
    if (!isxdigit(hex_buf[0]) || !isxdigit(hex_buf[1]))
      return data_size;

    sscanf(hex_buf, "%x", &num);
    data_buf[idx / 2] = (uint8_t) num;
    idx += 2;
  }
  data_size = idx / 2;
  return data_size;
}

int FmtUtils::HexStringToBytes(const std::string& hex_str, uint8_t* data_buf,
                               const size_t buf_len) {
  return HexStringToBytes(hex_str.c_str(), data_buf, buf_len);
}

bool FmtUtils::BytesToHexString(const uint8_t* data_buf, const size_t buf_len,
                                char* hex_str, const size_t hex_len) {
  if (data_buf == NULL || buf_len <= 0 || hex_str == NULL)
    return false;

  if (hex_len < buf_len * 2 + 1)
    return false;

  for (size_t idx = 0; idx < buf_len; idx++) {
    snprintf(hex_str + (2 * idx), BYTE_HEX_STR_SIZE, "%02x", data_buf[idx]);
  }
  hex_str[buf_len * 2] = '\0';

  return true;
}

std::string FmtUtils::BytesToHexString(const uint8_t* data_buf,
                                       const size_t buf_len) {
  std::unique_ptr<char[]> hex_str_buf;
  size_t hex_str_len = buf_len * 2 + 1;

  hex_str_buf = std::make_unique<char[]>(hex_str_len);
  if (!BytesToHexString(data_buf, buf_len, hex_str_buf.get(), hex_str_len))
    return "";

  return std::string(hex_str_buf.get());
}

void FmtUtils::FmtOutAsString(const std::string& data_str) {
  printf("%s\n", data_str.c_str());
}

void FmtUtils::FmtOutAsBytes(const std::string& data_str) {
  int buf_size;
  uint8_t data_buf[KEY_SIZE_BYTES];

  buf_size = HexStringToBytes(data_str, data_buf, KEY_SIZE_BYTES);
  for (int i = 0; i < buf_size; i++) {
    printf("%c", data_buf[i]);
  }
}

std::string FmtUtils::FmtOutAsSslSign(const std::string& signature,
                                      const std::string& fname) {
  return "RSA-SHA256(" + fname + ")= " + signature;
}

PubBigNum FmtUtils::PemPubToBigNum(const std::string& public_key,
                                   const int key_set) {
  PubBigNum pbn;
  size_t skip_bytes, mod_bytes, exp_bytes;

  if (key_set == RSA_1024_KEY_SET) {
    skip_bytes = 29;
  } else if (key_set == RSA_2048_KEY_SET) {
    skip_bytes = 33;
  } else {
    pbn.n[0] = '\0'; pbn.e[0] = '\0';
    return pbn;
  }

  mod_bytes = key_set / 8;
  exp_bytes = 3;

  std::string n = public_key.substr(skip_bytes * 2, mod_bytes * 2);
  std::string e = public_key.substr(public_key.length() - exp_bytes * 2);
  snprintf(pbn.n, n.length() + 1, "%s", n.c_str());
  snprintf(pbn.e, e.length() + 1, "%s", e.c_str());

  return pbn;
}

std::string FmtUtils::FmtOutAsPubBigNum(const std::string& public_key,
                                        const int key_set) {
  PubBigNum pbn = PemPubToBigNum(public_key, key_set);
  if (pbn.n[0] == '\0') {
    LOG(ERROR) << kClassName << MSG << "RSA public key length is not support";
    return "";
  }

  std::string n_str = "n = 0x" + std::string(pbn.n);
  std::string e_str = "e = 0x" + std::string(pbn.e);
  return n_str + "\n" + e_str;
}

std::string FmtUtils::ReadText(const std::string& fpath) {
  std::ifstream infile(fpath.c_str());
  std::string rdtxt((std::istreambuf_iterator<char>(infile)),
                     std::istreambuf_iterator<char>());
  infile.close();
  return rdtxt;
}

bool FmtUtils::ReadText(const std::string& fpath,
                        std::vector<std::string>* tlist) {
  std::string line;
  std::ifstream infile(fpath);

  if (!infile.is_open() || tlist == NULL)
    return false;

  tlist->clear();
  while (getline(infile, line))
    tlist->push_back(line);

  infile.close();
  return true;
}

bool FmtUtils::ReadBytes(const std::string& fpath, uint8_t* data_buf,
                         const size_t buf_len) {
  FILE* fp;
  size_t ret;

  if (data_buf == NULL || buf_len <= 0)
    return false;

  fp = fopen(fpath.c_str(), kFileModeRb);
  if (fp == NULL)
    return false;

  ret = fread(data_buf, sizeof(uint8_t), buf_len, fp);
  fclose(fp);
  if (ret != buf_len)
    return false;

  return true;
}

std::string FmtUtils::ReadSha256Hash(const std::string& fpath) {
  uint8_t hash_data[SHA256_DIGEST_LENGTH];
  if (!ReadBytes(fpath, hash_data, SHA256_DIGEST_LENGTH)) {
    LOG(ERROR) << kClassName << MSG << "Failed to read data from: " << fpath;
    return "";
  }
  return BytesToHexString(hash_data, SHA256_DIGEST_LENGTH);
}

void FmtUtils::WriteText(const std::string& fpath,
                         const std::string& data_str) {
  FILE* fp;

  fp = fopen(fpath.c_str(), kFileModeWt);
  fputs(data_str.c_str(), fp);
  LOG(INFO) << kClassName << MSG << "Text has been written to: " << fpath;
  fclose(fp);
}

void FmtUtils::WriteBytes(const std::string& fpath,
                          const std::string& data_str) {
  int buf_size;
  uint8_t data_buf[KEY_SIZE_BYTES];
  FILE* fp;

  buf_size = HexStringToBytes(data_str, data_buf, KEY_SIZE_BYTES);
  fp = fopen(fpath.c_str(), kFileModeWb);
  fwrite(data_buf, sizeof(uint8_t), buf_size, fp);
  LOG(INFO) << kClassName << MSG << "Bytes has been written to: " << fpath;
  fclose(fp);
}
