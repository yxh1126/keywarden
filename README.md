# keywarden

Welcome to "keywarden" repository

**keywarden** repo is Inceptio's uniform online signature service for
secure boot.

For any questions for this repo, please reach out to behuangyi@gmail.com


## Getting Started

* Build pre-requirement setup
  * Refer to Bazel manual https://bazel.build/install/ubuntu
  * Refer to gRPC manual https://grpc.io/docs/languages/python/quickstart/
  * `sudo apt install bazel-6.4.0`
  * `sudo apt install python3.8`
  * `sudo apt install libjson-c-dev libssl-dev` for dependency library
  * `python -m pip install --upgrade pip` for version 9.0.1 or higher
  * `python -m pip install grpcio` for gRPC Python libs
  * `python -m pip install grpcio-tools` for gRPC Python tools
  * `python -m pip install pycryptodome` for keydb generate

* Buid and run the server
  * `bazel run //server:run_server`

* Server API unit test
  * `bazel test ...`

* Run Python client tool
  * `bazel run //client/python:get_signature`
  * `bazel run //client/python:get_public`

* Run C++ client tool
  * `bazel run //client/cpp:get_signature`
  * `bazel run //client/cpp:get_public`


## Server Launcher

```
[gRPC Code Signing Server Launcher]
Command line parameters:
  -h [ --help ]                        Print the help message
  -p [ --port ] arg (=50051)           Server port for the code signing service
  -a [ --addr ] arg (=0.0.0.0)         Server IP address for the code signing
                                       service
  -d [ --keydb ] arg (=data/server.db) Path of the private key database for the
                                       code signing service
```


## Client Tools

* Python tools for both Windows and Linux
  * get_signature.py
  * get_public.py

* C++ tools are prepared for Linux
  * get_signature
  * get_public


## Common Bazel Commands

* Builds the specified targets: `bazel build <options> <targets>`, use `bazel build ...` to build all. (Modify BUILD file to build your own codes.)
* Runs the specified target: `bazel run <options> -- <binary target> <flags to binary>`
* Builds and runs the specified test targets: `bazel test <options> <test-targets>`, use `bazel test ...` to build all and run all test targets among them.
* Prints help for commands, or the index: `bazel help <command>`, highly recommend using help command to get more information of these commands and other commands like `clean`, `coverage`, etc.


## Code Style

https://google.github.io/styleguide/cppguide.html<br/>
You can use `clang-format` with style `Google` to format your code automatically.

Call `tools/cpplint.py` for google-lint on your .h & .cc file.<br/>
Call `bash tools/cpplint.sh` to run cpplint on every .h or .cc.<br/>
