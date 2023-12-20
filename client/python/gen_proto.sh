#!/bin/bash

# This bash tool will update the gRPC code used by our application to use the
# new service definition. It regenerates signserver_pb2.py which contains our
# generated request and response classes and signserver_pb2_grpc.py which
# contains our generated client and server classes.

python3 -m grpc_tools.protoc -I../../protos \
        --python_out=. \
        --pyi_out=. \
        --grpc_python_out=. ../../protos/signserver.proto
