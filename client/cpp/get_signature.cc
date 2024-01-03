//
// Copyright 2023 Yi Huang. All Rights Reserved.
//

#include <iostream>
#include <memory>
#include <string>

#include "utils/fmt_utils.h"
#include "utils/crypto_utils.h"
#include "utils/common.h"
#include "version/tool_version.h"
#include "client/common/rpc_sign_client.h"
#include "boost/program_options.hpp"

const constexpr char *kToolName = "[gRPC Code Signing Client - GetSignature]";

namespace po = boost::program_options;
using client::common::CodeSigningClient;
using utils::FmtUtils;
using utils::CryptoUtils;

int main(int argc, char** argv) {
  po::options_description desc("Command line parameters");
  desc.add_options()
    ("help,h", "Print the help message")
    ("version,v", "Print the tool version number")
    ("addr,a", po::value<std::string>()->default_value(SERVER_URL),
     "Server IP address for the code signing service")
    ("port,p", po::value<uint16_t>()->default_value(SERVER_PORT),
     "Server port for the code signing service")
    ("orig_file,o", po::value<std::string>(),
     "Path of the original file to get signature")
    ("hash_file,d", po::value<std::string>(),
     "Path of the hash file to get signature")
    ("hash_str,x", po::value<std::string>(),
     "Hash value as hex string to get signature")
    ("length,l", po::value<int>(), "Support key length either 2048 or 1024")
    ("id,i", po::value<int>(), "Key ID range from 1 to 8")
    ("fmt,f", po::value<char>()->default_value(FMT_RSA_SIGN_STR),
     "Format for display the signature: [s - text, b - binary, l - openssl]")
    ("tag,t", po::value<std::string>()->default_value(""),
     "Tag name for the Openssl format signature display")
    ("tofile,w", po::value<std::string>()->default_value(""),
     "Path for saving the signature");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  } catch(...) {
    std::cout << "Parameter type is not valid ...\n" << std::endl;
    std::cout << kToolName << std::endl << desc;
    return 1;
  }
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << kToolName << std::endl << desc;
    return 0;
  }

  if (vm.count("version")) {
    std::cout << kToolName << std::endl << KEYWARDEN_VERSION_NUM << std::endl;
    return 0;
  }

  int in_arg_cnt = 0;
  if (vm.count("orig_file")) in_arg_cnt++;
  if (vm.count("hash_file")) in_arg_cnt++;
  if (vm.count("hash_str")) in_arg_cnt++;

  if (!vm.count("length") || !vm.count("id") || in_arg_cnt != 1) {
    std::cout << "Required parameter does not match ...\n" << std::endl;
    std::cout << kToolName << std::endl << desc;
    return 1;
  }

  // Check optional parameter from user input
  char out_fmt = vm["fmt"].as<char>();
  std::string tag_name = vm["tag"].as<std::string>();
  std::string to_file = vm["tofile"].as<std::string>();

  // Get user input value for required parameter
  int key_set = vm["length"].as<int>();
  int key_id = vm["id"].as<int>();

  // Get hash string for required parameter
  std::string hash_str;
  if (vm.count("orig_file")) {
    std::string orig_file = vm["orig_file"].as<std::string>();
    tag_name = orig_file.substr(orig_file.find_last_of("/\\") + 1);
    hash_str = CryptoUtils::GetFileSha256Hash(orig_file);
  } else if (vm.count("hash_file")) {
    std::string hash_file = vm["hash_file"].as<std::string>();
    hash_str = FmtUtils::ReadSha256Hash(hash_file);
  } else {
    hash_str = vm["hash_str"].as<std::string>();
  }

  if (!CodeSigningClient::SigRequestCheck(hash_str, key_set, key_id,
                                          out_fmt, tag_name)) {
    std::cout << "Parameter error or format not support ...\n" << std::endl;
    std::cout << kToolName << std::endl << desc;
    return 1;
  }

  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  std::string the_addr = vm["addr"].as<std::string>();
  uint16_t the_port = vm["port"].as<uint16_t>();
  std::string server_info = the_addr + ":" + std::to_string(the_port);

  // We indicate that the channel isn't authenticated (use of
  // InsecureChannelCredentials()).
  CodeSigningClient client(
      grpc::CreateChannel(server_info, grpc::InsecureChannelCredentials()));

  // Signature format display to console or write to file
  client.FmtRsaSignature(hash_str, key_set, key_id, out_fmt, tag_name, to_file);

  return 0;
}
