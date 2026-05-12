package axonv1

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

const _ = grpc.SupportPackageIsVersion9

const IngressService_IngestStream_FullMethodName = "/axon.v1.IngressService/IngestStream"

type IngressServiceClient interface {
	IngestStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[IngestRequest, IngestResponse], error)
}

type ingressServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIngressServiceClient(cc grpc.ClientConnInterface) IngressServiceClient {
	return &ingressServiceClient{cc}
}

func (c *ingressServiceClient) IngestStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[IngestRequest, IngestResponse], error) {
	stream, err := c.cc.NewStream(ctx, &IngressService_ServiceDesc.Streams[0], IngressService_IngestStream_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[IngestRequest, IngestResponse]{ClientStream: stream}
	return x, nil
}

type IngressServiceServer interface {
	IngestStream(IngressService_IngestStreamServer) error
	mustEmbedUnimplementedIngressServiceServer()
}

type UnimplementedIngressServiceServer struct{}

func (UnimplementedIngressServiceServer) IngestStream(IngressService_IngestStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method IngestStream not implemented")
}
func (UnimplementedIngressServiceServer) mustEmbedUnimplementedIngressServiceServer() {}

type UnsafeIngressServiceServer interface {
	mustEmbedUnimplementedIngressServiceServer()
}

func RegisterIngressServiceServer(s grpc.ServiceRegistrar, srv IngressServiceServer) {
	s.RegisterService(&IngressService_ServiceDesc, srv)
}

func _IngressService_IngestStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(IngressServiceServer).IngestStream(&grpc.GenericServerStream[IngestRequest, IngestResponse]{ServerStream: stream})
}

type IngressService_IngestStreamServer interface {
	Send(*IngestResponse) error
	Recv() (*IngestRequest, error)
	grpc.ServerStream
}

var IngressService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "axon.v1.IngressService",
	HandlerType: (*IngressServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "IngestStream",
			Handler:       _IngressService_IngestStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "api/proto/v1/axon.proto",
}
