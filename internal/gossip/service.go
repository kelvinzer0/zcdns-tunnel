package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/config"
)

const (
	// DefaultGossipPort adalah port standar untuk komunikasi gosip.
	DefaultGossipPort = 7946
	maxPeersToSend    = 5 // Maksimum peer yang dikirim dalam heartbeat/sync
)

// Config menampung konfigurasi untuk GossipService.
type Config struct {
	ListenAddr       string
	ValidationDomain string
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
}

// GossipService mengelola keanggotaan klaster menggunakan protokol gossip.
type GossipService struct {
	config    Config
	localAddr string // Alamat IP:Port lokal dari node ini

	peersMu sync.RWMutex
	peers   map[string]*Peer // map[Addr]Peer

	conn *net.UDPConn // Koneksi UDP untuk mengirim/menerima pesan

	stopChan chan struct{}
	wg       sync.WaitGroup

	PeerUpdateChan chan struct{} // Channel untuk memberi tahu perubahan peer
}

// NewGossipService membuat instance GossipService baru.
func NewGossipService(cfg config.GossipConfig, validationDomain, publicAddr string) (*GossipService, error) {
	probeInterval, err := time.ParseDuration(cfg.ProbeInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid probe_interval: %w", err)
	}
	probeTimeout, err := time.ParseDuration(cfg.ProbeTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid probe_timeout: %w", err)
	}

	listenAddr := fmt.Sprintf(":%d", DefaultGossipPort)

	return &GossipService{
		config: Config{
			ListenAddr:       listenAddr,
			ValidationDomain: validationDomain,
			ProbeInterval:    probeInterval,
			ProbeTimeout:     probeTimeout,
		},
		localAddr: publicAddr, // Menggunakan alamat publik yang ditemukan
		peers:     make(map[string]*Peer),
		stopChan:  make(chan struct{}),
		PeerUpdateChan: make(chan struct{}, 1), // Buffered channel
	}, nil
}

// Start memulai layanan gossip, menemukan rekan, dan bergabung dengan klaster.
func (gs *GossipService) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", gs.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}
	gs.conn = conn
	logrus.Infof("Gossip service listening on %s, announcing as %s", gs.config.ListenAddr, gs.localAddr)

	// Tambahkan diri sendiri ke daftar peer
	gs.peersMu.Lock()
	gs.peers[gs.localAddr] = NewPeer(gs.localAddr)
	gs.peersMu.Unlock()

	gs.wg.Add(3)
	go gs.listenForMessages()
	go gs.sendHeartbeats()
	go gs.checkPeerStatus()

	// Temukan dan gabung dengan klaster
	go gs.discoverAndJoin(ctx)

	return nil
}

// discoverAndJoin secara berkala mencoba menemukan rekan dan bergabung dengan klaster.
func (gs *GossipService) discoverAndJoin(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second) // Coba lagi setiap 15 detik jika gagal
	defer ticker.Stop()

	// Coba segera saat startup
	gs.attemptJoin(ctx)

	for {
		select {
		case <-gs.stopChan:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			gs.attemptJoin(ctx)
		}
	}
}

func (gs *GossipService) attemptJoin(ctx context.Context) {
	// Jika kita sudah memiliki rekan selain diri sendiri, kita mungkin sudah terhubung.
	if gs.GetPeerCount() > 1 {
		return
	}

	logrus.Infof("Discovering peer IPs from validation domain: %s", gs.config.ValidationDomain)
	seedIPs, err := DiscoverPeerIPs(ctx, gs.config.ValidationDomain)
	if err != nil {
		logrus.Warnf("Failed to discover seed peers: %v", err)
		return
	}

	var seedPeers []string
	for _, ip := range seedIPs {
		seedPeers = append(seedPeers, fmt.Sprintf("%s:%d", ip.String(), DefaultGossipPort))
	}

	gs.join(seedPeers)
}

// Stop menghentikan layanan gossip.
func (gs *GossipService) Stop() {
	logrus.Info("Stopping gossip service...")
	close(gs.stopChan)
	gs.conn.Close()
	gs.wg.Wait()
	logrus.Info("Gossip service stopped.")
}

// join mencoba bergabung dengan klaster menggunakan seed peers.
func (gs *GossipService) join(seedPeers []string) {
	joinPayload, _ := json.Marshal(JoinPayload{NewPeer: gs.localAddr})
	msg := GossipMessage{
		Type:    MessageTypeJoin,
		Sender:  gs.localAddr,
		Payload: joinPayload,
	}
	msgBytes, _ := json.Marshal(msg)

	for _, seed := range seedPeers {
		if seed == gs.localAddr {
			continue
		}
		logrus.Debugf("Attempting to join cluster via seed peer: %s", seed)
		go gs.sendMessage(msgBytes, seed)
	}
}

// sendMessage mengirim pesan UDP ke alamat tujuan.
func (gs *GossipService) sendMessage(msg []byte, targetAddr string) {
	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		logrus.Errorf("Failed to resolve target address %s: %v", targetAddr, err)
		return
	}
	_, err = gs.conn.WriteToUDP(msg, addr)
	if err != nil {
		logrus.Errorf("Failed to send message to %s: %v", targetAddr, err)
	}
}

// listenForMessages mendengarkan pesan UDP yang masuk.
func (gs *GossipService) listenForMessages() {
	defer gs.wg.Done()
	buf := make([]byte, 65536) // Ukuran buffer UDP maksimum

	for {
		n, remoteAddr, err := gs.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-gs.stopChan:
				return // Shutdown
			default:
				logrus.Errorf("Error reading from UDP: %v", err)
				continue
			}
		}
		go gs.handleMessage(buf[:n], remoteAddr)
	}
}

// handleMessage memproses pesan gossip yang diterima.
func (gs *GossipService) handleMessage(msgBytes []byte, remoteAddr *net.UDPAddr) {
	var msg GossipMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		logrus.Warnf("Failed to unmarshal gossip message from %s: %v", remoteAddr.String(), err)
		return
	}

	switch msg.Type {
	case MessageTypeWhoAmI:
		logrus.Debugf("Received WhoAmI from %s", remoteAddr.String())
		payload, _ := json.Marshal(WhoAmIResponsePayload{PublicAddr: remoteAddr.String()})
		respMsg := GossipMessage{
			Type:    MessageTypeWhoAmIResponse,
			Sender:  gs.localAddr,
			Payload: payload,
		}
		respBytes, _ := json.Marshal(respMsg)
		gs.sendMessage(respBytes, remoteAddr.String())
		return // Tidak perlu proses lebih lanjut untuk pesan ini

	case MessageTypeJoin:
		var payload JoinPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal JoinPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Infof("Received JOIN from %s (new peer: %s)", msg.Sender, payload.NewPeer)
		gs.updatePeer(payload.NewPeer)

	case MessageTypeHeartbeat:
		var payload HeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal HeartbeatPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received HEARTBEAT from %s. Known peers in payload: %v", msg.Sender, payload.KnownPeers)
		for _, knownPeerAddr := range payload.KnownPeers {
			gs.updatePeer(knownPeerAddr)
		}

	case MessageTypeSync:
		var payload SyncPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal SyncPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received SYNC from %s. Full peer list: %v", msg.Sender, payload.Peers)
		for _, syncPeerAddr := range payload.Peers {
			gs.updatePeer(syncPeerAddr)
		}

	default:
		logrus.Warnf("Received unknown gossip message type: '%s' from %s", msg.Type, remoteAddr.String())
	}

	// Perbarui status pengirim
	gs.updatePeer(msg.Sender)
}

// updatePeer menambahkan atau memperbarui peer dalam daftar.
func (gs *GossipService) updatePeer(peerAddr string) {
	if peerAddr == "" || peerAddr == gs.localAddr {
		return
	}

	gs.peersMu.Lock()
	defer gs.peersMu.Unlock()

	if peer, ok := gs.peers[peerAddr]; ok {
		peer.UpdateLastSeen()
	} else {
		logrus.Infof("Discovered new peer: %s", peerAddr)
		gs.peers[peerAddr] = NewPeer(peerAddr)
		go gs.propagateNewPeer(peerAddr)
		select {
		case gs.PeerUpdateChan <- struct{}{}:
		default:
		}
	}
}

// propagateNewPeer mengirim pesan JOIN untuk peer baru ke subset peer yang diketahui.
func (gs *GossipService) propagateNewPeer(newPeerAddr string) {
	joinPayload, _ := json.Marshal(JoinPayload{NewPeer: newPeerAddr})
	msg := GossipMessage{
		Type:    MessageTypeJoin,
		Sender:  gs.localAddr,
		Payload: joinPayload,
	}
	msgBytes, _ := json.Marshal(msg)

	// Kirim ke beberapa peer acak
	targets := gs.GetRandomPeers(maxPeersToSend, false)
	for _, peerAddr := range targets {
		go gs.sendMessage(msgBytes, peerAddr)
	}
}

// sendHeartbeats secara berkala mengirim heartbeat ke peer acak.
func (gs *GossipService) sendHeartbeats() {
	defer gs.wg.Done()
	ticker := time.NewTicker(gs.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gs.stopChan:
			return
		case <-ticker.C:
			if gs.GetPeerCount() <= 1 {
				continue
			}

			heartbeatPayload, _ := json.Marshal(HeartbeatPayload{KnownPeers: gs.GetRandomPeers(maxPeersToSend, true)})
			msg := GossipMessage{
				Type:    MessageTypeHeartbeat,
				Sender:  gs.localAddr,
				Payload: heartbeatPayload,
			}
			msgBytes, _ := json.Marshal(msg)

			// Kirim heartbeat ke beberapa peer acak
			targets := gs.GetRandomPeers(maxPeersToSend, false)
			for _, target := range targets {
				go gs.sendMessage(msgBytes, target)
			}
		}
	}
}

// checkPeerStatus secara berkala memeriksa peer yang mati.
func (gs *GossipService) checkPeerStatus() {
	defer gs.wg.Done()
	ticker := time.NewTicker(gs.config.ProbeInterval) // Periksa sesering heartbeat
	defer ticker.Stop()

	for {
		select {
		case <-gs.stopChan:
			return
		case <-ticker.C:
			var deadPeers []string
			gs.peersMu.Lock()
			for addr, peer := range gs.peers {
				if addr == gs.localAddr {
					continue
				}
				if time.Since(peer.LastSeen) > gs.config.ProbeTimeout {
					deadPeers = append(deadPeers, addr)
				}
			}
			for _, addr := range deadPeers {
				logrus.Warnf("Peer %s detected as dead (last seen %s ago)", addr, time.Since(gs.peers[addr].LastSeen).Round(time.Second))
				delete(gs.peers, addr)
			}
			gs.peersMu.Unlock()

			if len(deadPeers) > 0 {
				select {
				case gs.PeerUpdateChan <- struct{}{}:
				default:
				}
			}
		}
	}
}

// GetActivePeerAddrs mengembalikan daftar alamat peer yang aktif.
func (gs *GossipService) GetActivePeerAddrs() []string {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()

	var active []string
	for addr := range gs.peers {
		active = append(active, addr)
	}
	return active
}

// GetRandomPeers mengembalikan slice acak dari peer yang aktif.
func (gs *GossipService) GetRandomPeers(count int, includeSelf bool) []string {
	activePeers := gs.GetActivePeerAddrs()

	if !includeSelf {
		// Hapus diri sendiri dari daftar
		for i, addr := range activePeers {
			if addr == gs.localAddr {
				activePeers = append(activePeers[:i], activePeers[i+1:]...)
				break
			}
		}
	}

	rand.Shuffle(len(activePeers), func(i, j int) {
		activePeers[i], activePeers[j] = activePeers[j], activePeers[i]
	})

	if len(activePeers) <= count {
		return activePeers
	}
	return activePeers[:count]
}

// GetPeerCount mengembalikan jumlah peer yang diketahui (termasuk diri sendiri).
func (gs *GossipService) GetPeerCount() int {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	return len(gs.peers)
}
