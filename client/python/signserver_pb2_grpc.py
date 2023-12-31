# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import signserver_pb2 as signserver__pb2


class CodeSigningStub(object):
    """The Inceptio code signing service definition
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetRsaSignature = channel.unary_unary(
                '/signserver.CodeSigning/GetRsaSignature',
                request_serializer=signserver__pb2.RsaSignRequest.SerializeToString,
                response_deserializer=signserver__pb2.RsaSignReply.FromString,
                )
        self.GetRsaPublicKey = channel.unary_unary(
                '/signserver.CodeSigning/GetRsaPublicKey',
                request_serializer=signserver__pb2.RsaPubkeyRequest.SerializeToString,
                response_deserializer=signserver__pb2.RsaPubkeyReply.FromString,
                )


class CodeSigningServicer(object):
    """The Inceptio code signing service definition
    """

    def GetRsaSignature(self, request, context):
        """Interface for getting the RSA signature
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetRsaPublicKey(self, request, context):
        """Interface for getting the RSA public key
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_CodeSigningServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetRsaSignature': grpc.unary_unary_rpc_method_handler(
                    servicer.GetRsaSignature,
                    request_deserializer=signserver__pb2.RsaSignRequest.FromString,
                    response_serializer=signserver__pb2.RsaSignReply.SerializeToString,
            ),
            'GetRsaPublicKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GetRsaPublicKey,
                    request_deserializer=signserver__pb2.RsaPubkeyRequest.FromString,
                    response_serializer=signserver__pb2.RsaPubkeyReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'signserver.CodeSigning', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class CodeSigning(object):
    """The Inceptio code signing service definition
    """

    @staticmethod
    def GetRsaSignature(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/signserver.CodeSigning/GetRsaSignature',
            signserver__pb2.RsaSignRequest.SerializeToString,
            signserver__pb2.RsaSignReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetRsaPublicKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/signserver.CodeSigning/GetRsaPublicKey',
            signserver__pb2.RsaPubkeyRequest.SerializeToString,
            signserver__pb2.RsaPubkeyReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
