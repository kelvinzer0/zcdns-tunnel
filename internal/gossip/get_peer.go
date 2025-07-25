package gossip

import (
	"net"
)

// GetPeer mengembalikan informasi peer berdasarkan alamat
func (gs *GossipService) GetPeer(addr string) *Peer {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	
	peer, exists := gs.peers[addr]
	if !exists {
		return nil
	}
	
	return peer
}
// GetListenAddr mengembalikan alamat listen untuk gossip service
func (gs *GossipService) GetListenAddr() string {
	return gs.config.ListenAddr
}

// GetLocalAddr mengembalikan alamat lokal node
func (gs *GossipService) GetLocalAddr() string {
	return gs.localAddr
}

// GetUDPConn mengembalikan koneksi UDP yang digunakan oleh gossip service
func (gs *GossipService) GetUDPConn() *net.UDPConn {
	return gs.conn
}