package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/config"
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
	// Always use the DefaultGossipPort (7946) for consistency
	listenAddr := fmt.Sprintf(":%d", DefaultGossipPort)
	gs.config.ListenAddr = listenAddr
	
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Try to listen with exponential backoff in case of temporary errors
	var conn *net.UDPConn
	var lastErr error
	
	for retries := 0; retries < 5; retries++ {
		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			break // Successfully established connection
		}
		
		lastErr = err
		
		// Check if this is a temporary error that might resolve with retry
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Temporary() {
				backoffTime := time.Duration(1<<uint(retries)) * 100 * time.Millisecond
				logrus.Warnf("Temporary error listening on UDP port %d, retrying in %v: %v", 
					DefaultGossipPort, backoffTime, err)
				time.Sleep(backoffTime)
				continue
			}
		}
		
		// Non-temporary error, no need to retry
		return fmt.Errorf("failed to listen UDP on port %d: %w", DefaultGossipPort, err)
	}
	
	if conn == nil {
		return fmt.Errorf("failed to listen UDP after multiple attempts: %w", lastErr)
	}
	
	gs.conn = conn
	logrus.Infof("Gossip service listening on %s, announcing as %s", listenAddr, gs.localAddr)

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
	joinPayload, _ := json.Marshal(JoinPayload{
		NewPeer:      gs.localAddr,
		GossipPort:   DefaultGossipPort,
	})
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

// sendMessage mengirim pesan UDP ke alamat tujuan dengan retry logic.
func (gs *GossipService) sendMessage(msg []byte, targetAddr string) {
	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		logrus.Errorf("Failed to resolve target address %s: %v", targetAddr, err)
		return
	}
	
	// Implement retry with exponential backoff
	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries
		if retry > 0 {
			backoffTime := time.Duration(1<<uint(retry-1)) * 200 * time.Millisecond
			logrus.Debugf("Retrying send to %s (attempt %d/%d) after %v", targetAddr, retry+1, maxRetries, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Set a timeout for the UDP write operation
		gs.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		
		_, err = gs.conn.WriteToUDP(msg, addr)
		
		// Reset the write deadline
		gs.conn.SetWriteDeadline(time.Time{})
		
		if err == nil {
			// Message sent successfully
			return
		}
		
		// Handle different error types
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logrus.Warnf("Timeout sending message to %s (attempt %d/%d), will retry", 
				targetAddr, retry+1, maxRetries)
		} else if opErr, ok := err.(*net.OpError); ok {
			if strings.Contains(opErr.Error(), "connection refused") {
				logrus.Warnf("Connection refused when sending message to %s (attempt %d/%d), peer may be down or port 7946 is blocked", 
					targetAddr, retry+1, maxRetries)
			} else {
				logrus.Warnf("Error sending message to %s (attempt %d/%d): %v", 
					targetAddr, retry+1, maxRetries, err)
			}
		} else {
			logrus.Warnf("Unknown error sending message to %s (attempt %d/%d): %v", 
				targetAddr, retry+1, maxRetries, err)
		}
		
		// Last retry failed
		if retry == maxRetries-1 {
			logrus.Errorf("Failed to send message to %s after %d attempts", targetAddr, maxRetries)
		}
	}
}

// listenForMessages mendengarkan pesan UDP yang masuk.
func (gs *GossipService) listenForMessages() {
	defer gs.wg.Done()
	buf := make([]byte, 65536) // Ukuran buffer UDP maksimum

	for {
		select {
		case <-gs.stopChan:
			return // Shutdown
		default:
			// Set read deadline untuk menghindari blocking selamanya
			gs.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			
			n, remoteAddr, err := gs.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, ini normal dan bukan error sebenarnya
					continue
				}
				
				// Untuk error lain, log dengan level debug saja untuk menghindari spam log
				if opErr, ok := err.(*net.OpError); ok {
					// Check for specific network errors that might be temporary
					if opErr.Temporary() {
						logrus.Debugf("Temporary UDP read error in gossip service: %s (%T)", opErr.Error(), opErr.Err)
					} else {
						// Log dengan detail tipe error untuk debugging
						logrus.Debugf("UDP read error in gossip service: %s (%T)", opErr.Error(), opErr.Err)
					}
				} else {
					logrus.Debugf("Non-timeout error reading from UDP in gossip service: %v", err)
				}
				continue
			}
			
			// Reset read deadline
			gs.conn.SetReadDeadline(time.Time{})
			
			// Proses pesan dalam goroutine terpisah untuk menghindari blocking
			msgCopy := make([]byte, n)
			copy(msgCopy, buf[:n])
			go gs.handleMessage(msgCopy, remoteAddr)
		}
	}
}

// handleMessage memproses pesan gossip yang diterima.
func (gs *GossipService) handleMessage(msgBytes []byte, remoteAddr *net.UDPAddr) {
	// First try to unmarshal as a regular JSON object to check the structure
	var rawMsg map[string]interface{}
	if err := json.Unmarshal(msgBytes, &rawMsg); err != nil {
		logrus.Warnf("Failed to unmarshal raw message from %s: %v", remoteAddr.String(), err)
		return
	}
	
	// Check if payload is a string/[]byte or an object
	if payload, ok := rawMsg["payload"]; ok {
		// If payload is an object, convert it to a JSON string
		if _, isMap := payload.(map[string]interface{}); isMap {
			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				logrus.Warnf("Failed to marshal payload object: %v", err)
				return
			}
			rawMsg["payload"] = payloadBytes
			
			// Re-marshal the message with the fixed payload
			fixedMsgBytes, err := json.Marshal(rawMsg)
			if err != nil {
				logrus.Warnf("Failed to re-marshal message: %v", err)
				return
			}
			msgBytes = fixedMsgBytes
		}
	}
	
	// Now unmarshal as a GossipMessage
	var msg GossipMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		logrus.Warnf("Failed to unmarshal gossip message from %s: %v", remoteAddr.String(), err)
		return
	}

	switch msg.Type {
	case MessageTypeWhoAmI:
		logrus.Debugf("Received WhoAmI from %s", remoteAddr.String())
		payload, _ := json.Marshal(WhoAmIResponsePayload{PublicAddr: fmt.Sprintf("%s:%d", remoteAddr.IP.String(), DefaultGossipPort)})
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
		gs.updatePeer(payload.NewPeer, payload.SSHListenAddr, payload.GossipPort)

	case MessageTypeHeartbeat:
		var payload HeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal HeartbeatPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received HEARTBEAT from %s. Known peers in payload: %v", msg.Sender, payload.KnownPeers)
		for _, knownPeerAddr := range payload.KnownPeers {
			gs.updatePeer(knownPeerAddr, "", 0)
		}
		// Update sender with its SSH listen address and gossip port if provided
		gs.updatePeer(msg.Sender, payload.SSHListenAddr, payload.GossipPort)

	case MessageTypeSync:
		var payload SyncPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal SyncPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received SYNC from %s. Full peer list: %v", msg.Sender, payload.Peers)
		for _, syncPeerAddr := range payload.Peers {
			gs.updatePeer(syncPeerAddr, "", 0)
		}
		// Always update the sender
		gs.updatePeer(msg.Sender, "", 0)

	default:
		logrus.Warnf("Received unknown gossip message type: '%s' from %s", msg.Type, remoteAddr.String())
	}

	// Perbarui status pengirim
	gs.updatePeer(msg.Sender, "", 0)
}

// updatePeer menambahkan atau memperbarui peer dalam daftar.
func (gs *GossipService) updatePeer(peerAddr string, sshListenAddr string, gossipPort int) {
	if peerAddr == "" || peerAddr == gs.localAddr {
		return
	}

	gs.peersMu.Lock()
	defer gs.peersMu.Unlock()

	if peer, ok := gs.peers[peerAddr]; ok {
		peer.UpdateLastSeen()
		// Update additional information if provided
		if sshListenAddr != "" {
			peer.SSHListenAddr = sshListenAddr
		}
		if gossipPort > 0 {
			peer.GossipPort = gossipPort
		}
	} else {
		logrus.Infof("Discovered new peer: %s", peerAddr)
		newPeer := NewPeer(peerAddr)
		if sshListenAddr != "" {
			newPeer.SSHListenAddr = sshListenAddr
		}
		if gossipPort > 0 {
			newPeer.GossipPort = gossipPort
		}
		gs.peers[peerAddr] = newPeer
		go gs.propagateNewPeer(peerAddr, sshListenAddr, gossipPort)
		select {
		case gs.PeerUpdateChan <- struct{}{}:
		default:
		}
	}
}

// propagateNewPeer mengirim pesan JOIN untuk peer baru ke subset peer yang diketahui.
func (gs *GossipService) propagateNewPeer(newPeerAddr string, sshListenAddr string, gossipPort int) {
	joinPayload, _ := json.Marshal(JoinPayload{
		NewPeer:      newPeerAddr,
		SSHListenAddr: sshListenAddr,
		GossipPort:   gossipPort,
	})
	msg := GossipMessage{
		Type:    MessageTypeJoin,
		Sender:  gs.localAddr,
		Payload: joinPayload,
	}
	msgBytes, _ := json.Marshal(msg)

	// Kirim ke beberapa peer acak
	targets := gs.GetRandomPeers(MaxPeersToSend, false)
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

			heartbeatPayload, _ := json.Marshal(HeartbeatPayload{
				KnownPeers: gs.GetRandomPeers(MaxPeersToSend, true),
				GossipPort: DefaultGossipPort,
			})
			msg := GossipMessage{
				Type:    MessageTypeHeartbeat,
				Sender:  gs.localAddr,
				Payload: heartbeatPayload,
			}
			msgBytes, _ := json.Marshal(msg)

			// Kirim heartbeat ke beberapa peer acak
			targets := gs.GetRandomPeers(MaxPeersToSend, false)
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
					peer.MarkDead() // Mark as dead before collecting for deletion
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

// isPortOpen checks if a TCP port is open on a given address
func isPortOpen(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GetPreferredConnectionAddress returns the best address to use for connecting to a peer
func (gs *GossipService) GetPreferredConnectionAddress(peerAddr string) string {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	
	peer, exists := gs.peers[peerAddr]
	if !exists {
		return peerAddr // Default to the original address if peer not found
	}
	
	// Extract the IP from the peer address (remove the port)
	host, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return peerAddr // Return original if we can't parse it
	}
	
	// Try the gossip port first if it's known
	if peer.GossipPort > 0 {
		gossipAddr := fmt.Sprintf("%s:%d", host, peer.GossipPort)
		if isPortOpen(gossipAddr, 2*time.Second) {
			return gossipAddr
		}
	}
	
	// Fall back to the original address
	return peerAddr
}
// GetPeerUpdateChan returns the channel that is notified when the peer list changes
func (gs *GossipService) GetPeerUpdateChan() <-chan struct{} {
	return gs.PeerUpdateChan
}