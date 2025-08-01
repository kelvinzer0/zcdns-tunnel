package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/grpc"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// sshForwardHandler implements the grpc.ForwardHandler and grpc.IntermediaryAddrHandler interfaces
type sshForwardHandler struct {
	server *SSHServer
	
	// Map to store intermediary addresses shared by other nodes
	// Key is domain:protocol:port, value is intermediary address
	sharedIntermediaryAddrs sync.Map
}
// Ensure sshForwardHandler implements both interfaces
var (
	_ grpc.ForwardHandler = (*sshForwardHandler)(nil)
	_ grpc.IntermediaryAddrHandler = (*sshForwardHandler)(nil)
)

// newSSHForwardHandler creates a new SSH forward handler
func newSSHForwardHandler(server *SSHServer) interface {
	grpc.ForwardHandler
	grpc.IntermediaryAddrHandler
} {
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
	
	// Log detailed information about node responsibility
	logrus.WithFields(logrus.Fields{
		"domain":           req.Domain,
		"responsible_node": responsibleNode,
		"current_node":     h.server.LocalGossipAddr,
		"is_responsible":   responsibleNode == h.server.LocalGossipAddr,
	}).Info("Checking node responsibility for domain")
	
	if responsibleNode != h.server.LocalGossipAddr {
		errMsg := fmt.Sprintf("Node ini (%s) tidak bertanggung jawab untuk domain %s, node yang bertanggung jawab adalah %s",
			h.server.LocalGossipAddr, req.Domain, responsibleNode)
		logrus.Warn(errMsg)

		// Log the active peers in the consistent hash ring for debugging
		activePeers := h.server.GossipService.GetActivePeerAddrs()
		logrus.WithFields(logrus.Fields{
			"domain":           req.Domain,
			"responsible_node": responsibleNode,
			"current_node":     h.server.LocalGossipAddr,
			"active_peers":     activePeers,
			"peer_count":       len(activePeers),
		}).Warn("Not responsible for domain, rejecting forward request")

		return &pb.ForwardResponseMessage{
			ForwardId: req.ForwardId,
			Success:   false,
			Error:     errMsg,
		}, nil
	}

	// Process the forward request
	// This is a placeholder - in a real implementation, you would handle the actual forwarding
	// For now, we'll just return a success response with the same port
	logrus.WithFields(logrus.Fields{
		"domain":        req.Domain,
		"bind_addr":     req.BindAddr,
		"bind_port":     req.BindPort,
		"forward_id":    req.ForwardId,
		"original_addr": req.OriginalAddr,
	}).Info("Successfully handled forward request, returning success response")
	
	return &pb.ForwardResponseMessage{
		ForwardId: req.ForwardId,
		Success:   true,
		Port:      req.BindPort,
	}, nil
}

// HandleShareIntermediaryAddr handles a share intermediary address request
func (h *sshForwardHandler) HandleShareIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrMessage) (bool, error) {
	logrus.WithFields(logrus.Fields{
		"domain":           req.Domain,
		"protocol_prefix":  req.ProtocolPrefix,
		"public_port":      req.PublicPort,
		"intermediary_addr": req.IntermediaryAddr,
		"forward_id":       req.ForwardId,
		"sender":           req.Sender.Address,
	}).Info("Handling share intermediary address request")

	// Store the intermediary address in the shared state
	key := fmt.Sprintf("%s:%s:%d", req.Domain, req.ProtocolPrefix, req.PublicPort)
	h.sharedIntermediaryAddrs.Store(key, req.IntermediaryAddr)
	
	logrus.WithFields(logrus.Fields{
		"key":               key,
		"intermediary_addr": req.IntermediaryAddr,
	}).Info("Stored intermediary address in shared state")

	return true, nil
}

// HandleGetIntermediaryAddr handles a get intermediary address request
func (h *sshForwardHandler) HandleGetIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrRequest) (*pb.IntermediaryAddrMessage, error) {
	logrus.WithFields(logrus.Fields{
		"domain":          req.Domain,
		"protocol_prefix": req.ProtocolPrefix,
		"public_port":     req.PublicPort,
		"forward_id":      req.ForwardId,
		"sender":          req.Sender.Address,
	}).Info("Handling get intermediary address request")

	// Get the intermediary address from the shared state
	key := fmt.Sprintf("%s:%s:%d", req.Domain, req.ProtocolPrefix, req.PublicPort)
	intermediaryAddr, ok := h.sharedIntermediaryAddrs.Load(key)
	
	// Log the result of the lookup
	logFields := logrus.Fields{
		"key":            key,
		"domain":         req.Domain,
		"protocol_prefix": req.ProtocolPrefix,
		"public_port":    req.PublicPort,
		"found_in_shared": ok,
	}
	
	if !ok {
		logrus.WithFields(logFields).Warn("Intermediary address not found in shared state")
		
		// Try to get it from the tunnel manager
		addrStr, ok := h.server.Manager.LoadBridgeAddress(req.Domain, req.ProtocolPrefix, req.PublicPort)
		if !ok {
			logrus.WithFields(logFields).Warn("Intermediary address not found in tunnel manager")
			
			// Log active bridge addresses for debugging
			h.logActiveBridgeAddresses()
			
			return &pb.IntermediaryAddrMessage{
				Domain:          req.Domain,
				ProtocolPrefix:  req.ProtocolPrefix,
				PublicPort:      req.PublicPort,
				IntermediaryAddr: "",
				ForwardId:       req.ForwardId,
				Sender: &pb.Node{
					Address:    h.server.LocalGossipAddr,
					GossipPort: int32(h.server.Config.Gossip.GrpcPort),
				},
			}, nil
		}
		
		logFields["found_in_manager"] = true
		logFields["intermediary_addr"] = addrStr
		logrus.WithFields(logFields).Info("Retrieved intermediary address from tunnel manager")
		intermediaryAddr = addrStr
	} else {
		logFields["intermediary_addr"] = intermediaryAddr
		logrus.WithFields(logFields).Info("Retrieved intermediary address from shared state")
	}

	return &pb.IntermediaryAddrMessage{
		Domain:          req.Domain,
		ProtocolPrefix:  req.ProtocolPrefix,
		PublicPort:      req.PublicPort,
		IntermediaryAddr: intermediaryAddr.(string),
		ForwardId:       req.ForwardId,
		Sender: &pb.Node{
			Address:    h.server.LocalGossipAddr,
			GossipPort: int32(h.server.Config.Gossip.GrpcPort),
		},
	}, nil
}

// logActiveBridgeAddresses logs all active bridge addresses for debugging
func (h *sshForwardHandler) logActiveBridgeAddresses() {
	// Log all shared intermediary addresses
	addresses := make(map[string]string)
	h.sharedIntermediaryAddrs.Range(func(key, value interface{}) bool {
		addresses[key.(string)] = value.(string)
		return true
	})
	
	logrus.WithFields(logrus.Fields{
		"shared_addresses": addresses,
		"count":            len(addresses),
	}).Info("Current shared intermediary addresses")
}