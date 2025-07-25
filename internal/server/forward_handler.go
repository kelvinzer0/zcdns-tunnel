package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/grpc"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// sshForwardHandler implements the grpc.ForwardHandler interface
type sshForwardHandler struct {
	server *SSHServer
}

// newSSHForwardHandler creates a new SSH forward handler
func newSSHForwardHandler(server *SSHServer) grpc.ForwardHandler {
	return &sshForwardHandler{
		server: server,
	}
}

// HandleForwardRequest handles a forward request
func (h *sshForwardHandler) HandleForwardRequest(ctx context.Context, req *pb.ForwardRequestMessage) (*pb.ForwardResponseMessage, error) {
	logrus.WithFields(logrus.Fields{
		"domain":        req.Domain,
		"bind_addr":     req.BindAddr,
		"bind_port":     req.BindPort,
		"forward_id":    req.ForwardId,
		"original_addr": req.OriginalAddr,
		"sender":        req.Sender.Address,
	}).Info("Handling gRPC forward request")

	// Check if this node is responsible for the domain
	responsibleNode := h.server.ConsistentHash.Get(req.Domain)
	if responsibleNode != h.server.LocalGossipAddr {
		errMsg := fmt.Sprintf("Node ini (%s) tidak bertanggung jawab untuk domain %s, node yang bertanggung jawab adalah %s",
			h.server.LocalGossipAddr, req.Domain, responsibleNode)
		logrus.Warn(errMsg)

		return &pb.ForwardResponseMessage{
			ForwardId: req.ForwardId,
			Success:   false,
			Error:     errMsg,
		}, nil
	}

	// Process the forward request
	// This is a placeholder - in a real implementation, you would handle the actual forwarding
	// For now, we'll just return a success response with the same port
	return &pb.ForwardResponseMessage{
		ForwardId: req.ForwardId,
		Success:   true,
		Port:      req.BindPort,
	}, nil
}