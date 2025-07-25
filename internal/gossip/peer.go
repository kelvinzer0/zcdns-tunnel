package gossip

import (
	"sync"
	"time"
)

// Peer merepresentasikan node lain dalam klaster.
type Peer struct {
	Addr         string    // IP:Port dari peer
	LastSeen     time.Time // Kapan terakhir kali peer ini mengirim heartbeat
	IsAlive      bool      // Status hidup/mati peer
	SSHListenAddr string   // SSH listen address of the peer
	GossipPort   int       // Gossip port for direct communication
	mu           sync.RWMutex
}

func NewPeer(addr string) *Peer {
	return &Peer{
		Addr:       addr,
		LastSeen:   time.Now(),
		IsAlive:    true,
		GossipPort: DefaultGossipPort,
	}
}

func (p *Peer) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastSeen = time.Now()
	p.IsAlive = true
}

func (p *Peer) MarkDead() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.IsAlive = false
}

func (p *Peer) GetStatus() (time.Time, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.LastSeen, p.IsAlive
}
