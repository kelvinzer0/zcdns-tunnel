package common

import (
	"context"
	"net"
)

// UDPProvider defines an interface for components that provide UDP connectivity
type UDPProvider interface {
	// GetUDPConn returns the UDP connection used by the service
	GetUDPConn() *net.UDPConn
	
	// GetListenAddr returns the listen address used by the service
	GetListenAddr() string
	
	// GetLocalAddr returns the local address of the node
	GetLocalAddr() string
}

// GossipProvider defines an interface for gossip protocol implementations
type GossipProvider interface {
	// Start starts the gossip service
	Start(ctx context.Context) error
	
	// Stop stops the gossip service
	Stop()
	
	// GetActivePeerAddrs returns the addresses of active peers
	GetActivePeerAddrs() []string
	
	// GetPeerUpdateChan returns a channel that is notified when the peer list changes
	GetPeerUpdateChan() <-chan struct{}
	
	// GetLocalAddr returns the local address of the node
	GetLocalAddr() string
}