package gossip

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