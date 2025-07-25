package common

import (
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
