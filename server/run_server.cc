//
// Copyright 2023 Inceptio Technology. All Rights Reserved.
//

#include <sys/stat.h>
#include <iostream>
#include <memory>
#include <string>

#include "server/rpc_sign_server.h"
#include "utils/common.h"
#include "version/tool_version.h"
#include "boost/program_options.hpp"
#include "grpcpp/ext/proto_server_reflection_plugin.h"
#include "grpcpp/health_check_service_interface.h"
#include "glog/logging.h"

const constexpr char *kToolName = "[gRPC Code Signing Server Launcher]";

namespace po = boost::program_options;
using grpc::Server;
using grpc::ServerBuilder;
using server::CodeSigningService;

int RunServer(const uint16_t port, const std::string& addr,
              const std::string& key_db) {
  std::string server_info = addr + ":" + std::to_string(port);
  CodeSigningService service(key_db);
  if (!service.GetServerStatus()) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "T_T Orz, failed to launching server ...";
    return 1;
  }

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_info, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());

  LOG(INFO) << kToolName;
  LOG(INFO) << "Server is listening on " << server_info;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
  return 0;
}

int main(int argc, char** argv) {
  FLAGS_logtostderr = 1;
  google::InitGoogleLogging(argv[0]);

  po::options_description desc("Command line parameters");
  desc.add_options()
    ("help,h", "Print the help message")
    ("version,v", "Print the tool version number")
    ("port,p", po::value<uint16_t>()->default_value(SERVER_PORT),
     "Server port for the code signing service")
    ("addr,a", po::value<std::string>()->default_value(SERVER_ADDR),
     "Server IP address for the code signing service")
    ("keydb,d", po::value<std::string>()->default_value("data/server.db"),
     "Path of the private key database for the code signing service");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  } catch(...) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "Input parameter is invalid ...";
    LOG(ERROR) << desc;
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

  uint16_t the_port = vm["port"].as<uint16_t>();
  std::string the_addr = vm["addr"].as<std::string>();
  std::string the_keydb = vm["keydb"].as<std::string>();

  struct stat sb;
  if (stat(the_keydb.c_str(), &sb) == -1) {
    LOG(ERROR) << kToolName;
    LOG(ERROR) << "The key database: <" << the_keydb << "> is invalid ...";
    LOG(ERROR) << desc;
    return 1;
  }

  return RunServer(the_port, the_addr, the_keydb);
}
