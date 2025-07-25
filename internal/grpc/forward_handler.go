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

// SetForwardHandler sets the handler for forward requests
func (s *GRPCServer) SetForwardHandler(handler ForwardHandler) {
	s.forwardHandler = handler
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