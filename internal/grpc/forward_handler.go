package grpc

import (
	"context"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// ForwardHandler defines an interface for handling forward requests
type ForwardHandler interface {
	// HandleForwardRequest handles a forward request
	HandleForwardRequest(ctx context.Context, req *pb.ForwardRequestMessage) (*pb.ForwardResponseMessage, error)
}

// IntermediaryAddrHandler defines an interface for handling intermediary address sharing
type IntermediaryAddrHandler interface {
	// HandleShareIntermediaryAddr handles a share intermediary address request
	HandleShareIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrMessage) (bool, error)
	
	// HandleGetIntermediaryAddr handles a get intermediary address request
	HandleGetIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrRequest) (*pb.IntermediaryAddrMessage, error)
}

// SetForwardHandler sets the handler for forward requests
func (s *GRPCServer) SetForwardHandler(handler interface{}) {
	if fwdHandler, ok := handler.(ForwardHandler); ok {
		s.forwardHandler = fwdHandler
	}
}

// forwardHandler is the handler for forward requests
var _ ForwardHandler = (*defaultForwardHandler)(nil)

// defaultForwardHandler is the default implementation of ForwardHandler
type defaultForwardHandler struct{}

// HandleForwardRequest handles a forward request
func (h *defaultForwardHandler) HandleForwardRequest(ctx context.Context, req *pb.ForwardRequestMessage) (*pb.ForwardResponseMessage, error) {
	// This is a placeholder - the actual implementation will be provided by the SSH server
	return &pb.ForwardResponseMessage{
		ForwardId: req.ForwardId,
		Success:   false,
		Error:     "No forward handler registered",
	}, nil
}
// IntermediaryAddrHandlerInstance returns the IntermediaryAddrHandler instance
func (s *GRPCServer) IntermediaryAddrHandlerInstance() (IntermediaryAddrHandler, bool) {
	if s.forwardHandler == nil {
		return nil, false
	}
	
	if handler, ok := s.forwardHandler.(IntermediaryAddrHandler); ok {
		return handler, true
	}
	
	return nil, false
}