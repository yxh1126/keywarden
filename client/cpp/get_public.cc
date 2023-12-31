//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#include <iostream>
#include <memory>
#include <string>

#include "utils/common.h"
#include "version/tool_version.h"
#include "client/common/rpc_sign_client.h"
#include "boost/program_options.hpp"

const constexpr char *kToolName = "[gRPC Code Signing Client - GetPublicKey]";

namespace po = boost::program_options;
using client::common::CodeSigningClient;

int main(int argc, char** argv) {
  FLAGS_logtostderr = 1;
  google::InitGoogleLogging(argv[0]);

  po::options_description desc("Command line parameters");
  desc.add_options()
    ("help,h", "Print the help message")
    ("version,v", "Print the tool version number")
    ("addr,a", po::value<std::string>()->default_value(SERVER_URL),
     "Server IP address for the code signing service")
    ("port,p", po::value<uint16_t>()->default_value(SERVER_PORT),
     "Server port for the code signing service")
    ("length,l", po::value<int>(), "Support key length either 2048 or 1024")
    ("id,i", po::value<int>(), "Key ID range from 1 to 8")
    ("type,t", po::value<std::string>(),
     "Public key type: [pem, der, sign, nxp, aurix]")
    ("fmt,f", po::value<char>()->default_value(FMT_RSA_PUB_STR),
     "Format for display the public key: [s - str, b - bin, n - mod, h - hash]")
    ("tofile,w", po::value<std::string>()->default_value(""),
     "Path for saving the public key");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  } catch(...) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "Parameter type is not valid ...";
    return 1;
  }
  po::notify(vm);

  if (vm.count("help")) {
    LOG(INFO) << kToolName;
    LOG(INFO) << desc;
    return 0;
  }

  if (vm.count("version")) {
    LOG(INFO) << kToolName;
    LOG(INFO) << KEYWARDEN_VERSION_NUM;
    return 0;
  }

  if (!vm.count("length") || !vm.count("id") || !vm.count("type")) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "Required parameter is missing ...";
    return 1;
  }

  // Check optional parameter from user input
  char out_fmt = vm["fmt"].as<char>();
  std::string to_file = vm["tofile"].as<std::string>();

  // Get user input value for required parameter
  int key_set = vm["length"].as<int>();
  int key_id = vm["id"].as<int>();
  std::string the_type = vm["type"].as<std::string>();

  // Check required key type parameter
  int key_type = -1;
  if (the_type == NXP_PUB_TYPE) {
    key_type = JOB_LX2160_PUB;
  } else if (the_type == PUB_PEM_TYPE) {
    key_type = JOB_J5_PUB_PEM;
  } else if (the_type == PUB_DER_TYPE) {
    key_type = JOB_J5_PUB_DER;
  } else if (the_type == PUB_SIG_TYPE) {
    key_type = JOB_J5_PUB_SIG;
  } else if (the_type == AURIX_PUB_TYPE && (
             out_fmt == FMT_RSA_PUB_STR ||
             out_fmt == FMT_RSA_PUB_NUM)) {
    key_type = JOB_J5_PUB_DER;
    out_fmt = FMT_RSA_PUB_NUM;
  } else {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "Key type parameter or dispaly format is not valid ...";
    return 1;
  }

  if (!CodeSigningClient::PubRequestCheck(key_set, key_id, key_type, out_fmt)) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "Parameter error or format not support ...";
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

  // Public key format display to console or write to file
  client.FmtRsaPublicKey(key_set, key_id, key_type, out_fmt, to_file);

  return 0;
}
