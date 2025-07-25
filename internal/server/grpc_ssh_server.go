package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/common"
	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/grpc"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// NewGRPCSSHServer creates a new SSH server that uses gRPC for communication
func NewGRPCSSHServer(cfg config.ServerConfig, gossipProvider common.GossipProvider, localGossipAddr string) (*SSHServer, error) {
	// Create the SSH server using the existing NewSSHServer function
	server, err := NewSSHServer(cfg, gossipProvider, localGossipAddr)
	if err != nil {
		return nil, err
	}

	// Create a gRPC client for communication with other nodes
	grpcClient := grpc.NewGRPCClient(cfg.Gossip, localGossipAddr)

	// Set up the server to handle forward requests
	if grpcServer, ok := gossipProvider.(*grpc.GRPCServer); ok {
		// Register the SSH server as the forward handler
		grpcServer.SetForwardHandler(newSSHForwardHandler(server))
	} else {
		logrus.Warn("GossipProvider is not a GRPCServer, forward handling will not work")
	}

	// Store the gRPC client in the server for later use
	server.GRPCClient = grpcClient

	return server, nil
}

// sshForwardHandler implements the grpc.ForwardHandler interface
type sshForwardHandler struct {
	server *SSHServer
}

// newSSHForwardHandler creates a new SSH forward handler
func newSSHForwardHandler(server *SSHServer) *sshForwardHandler {
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
	}).Info("Handling forward request")

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
	return &pb.ForwardResponseMessage{
		ForwardId: req.ForwardId,
		Success:   true,
		Port:      req.BindPort,
	}, nil
}