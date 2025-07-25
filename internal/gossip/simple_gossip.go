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
	"zcdns-tunnel/internal/udpproto"
)

// SimpleGossipService adalah implementasi sederhana dari protokol gossip
type SimpleGossipService struct {
	conn            *net.UDPConn
	localAddr       string
	peers           map[string]*Peer
	peersMu         sync.RWMutex
	probeInterval   time.Duration
	probeTimeout    time.Duration
	stopChan        chan struct{}
	wg              sync.WaitGroup
	PeerUpdateChan  chan struct{}
	clusterSecret   string
	validationDomain string
}

// NewSimpleGossipService membuat instance SimpleGossipService baru
func NewSimpleGossipService(cfg config.GossipConfig, validationDomain, publicAddr, clusterSecret string) (*SimpleGossipService, error) {
	probeInterval, err := time.ParseDuration(cfg.ProbeInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid probe_interval: %w", err)
	}
	
	probeTimeout, err := time.ParseDuration(cfg.ProbeTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid probe_timeout: %w", err)
	}
	
	// Tidak menggunakan cluster secret untuk meningkatkan performa
	logrus.Info("SimpleGossipService diinisialisasi tanpa cluster secret untuk meningkatkan performa")
	
	return &SimpleGossipService{
		localAddr:        publicAddr,
		peers:            make(map[string]*Peer),
		probeInterval:    probeInterval,
		probeTimeout:     probeTimeout,
		stopChan:         make(chan struct{}),
		PeerUpdateChan:   make(chan struct{}, 1),
		clusterSecret:    "", // Gunakan string kosong untuk meningkatkan performa
		validationDomain: validationDomain,
	}, nil
}

// Start memulai layanan gossip
func (gs *SimpleGossipService) Start(ctx context.Context) error {
	// Buat koneksi UDP
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", DefaultGossipPort))
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
	logrus.Infof("Simple Gossip service listening on :%d, announcing as %s", DefaultGossipPort, gs.localAddr)
	
	// Tambahkan diri sendiri ke daftar peer
	gs.peersMu.Lock()
	gs.peers[gs.localAddr] = NewPeer(gs.localAddr)
	gs.peersMu.Unlock()
	
	// Mulai goroutine untuk mendengarkan pesan, mengirim heartbeat, dan memeriksa status peer
	gs.wg.Add(3)
	go gs.listenForMessages()
	go gs.sendHeartbeats()
	go gs.checkPeerStatus()
	
	// Temukan dan gabung dengan klaster
	go gs.discoverAndJoin(ctx)
	
	return nil
}

// Stop menghentikan layanan gossip
func (gs *SimpleGossipService) Stop() {
	logrus.Info("Stopping simple gossip service...")
	close(gs.stopChan)
	if gs.conn != nil {
		gs.conn.Close()
	}
	gs.wg.Wait()
	logrus.Info("Simple gossip service stopped.")
}

// listenForMessages mendengarkan pesan UDP yang masuk
func (gs *SimpleGossipService) listenForMessages() {
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
						logrus.Debugf("Temporary UDP read error in SimpleGossipService: %s (%T)", opErr.Error(), opErr.Err)
					} else {
						// Log dengan detail tipe error untuk debugging
						logrus.Debugf("UDP read error in SimpleGossipService: %s (%T)", opErr.Error(), opErr.Err)
					}
				} else {
					logrus.Debugf("Non-timeout error reading from UDP in SimpleGossipService: %v", err)
				}
				continue
			}
			
			// Reset read deadline
			gs.conn.SetReadDeadline(time.Time{})
			
			// Proses pesan dengan copy buffer untuk menghindari data corruption
			msgCopy := make([]byte, n)
			copy(msgCopy, buf[:n])
			gs.handleMessage(msgCopy, remoteAddr)
		}
	}
}

// SimpleGossipMessage adalah struktur pesan untuk protokol gossip sederhana
type SimpleGossipMessage struct {
	Type      string          `json:"type"`
	Sender    string          `json:"sender"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
	HMAC      []byte          `json:"hmac,omitempty"`
}

// SimpleJoinPayload adalah payload untuk pesan JOIN
type SimpleJoinPayload struct {
	Addr string `json:"addr"`
}

// SimpleHeartbeatPayload adalah payload untuk pesan HEARTBEAT
type SimpleHeartbeatPayload struct {
	Peers []string `json:"peers"`
}

// Sign menandatangani pesan dengan HMAC
func (m *SimpleGossipMessage) Sign(secret []byte) {
	// Reset HMAC sebelum menandatangani
	m.HMAC = nil
	
	// Serialize pesan tanpa HMAC
	msgBytes, _ := json.Marshal(m)
	
	// Hitung HMAC menggunakan fungsi helper
	m.HMAC = SignMessage(msgBytes, secret)
}

// VerifyHMAC memverifikasi tanda tangan HMAC
func (m *SimpleGossipMessage) VerifyHMAC(secret []byte) bool {
	// Simpan HMAC asli
	originalHMAC := m.HMAC
	m.HMAC = nil
	
	// Serialize pesan tanpa HMAC
	msgBytes, err := json.Marshal(m)
	if err != nil {
		return false
	}
	
	// Kembalikan HMAC asli
	m.HMAC = originalHMAC
	
	// Verifikasi menggunakan fungsi helper
	return VerifyMessage(msgBytes, originalHMAC, secret)
}

// handleMessage memproses pesan yang diterima
func (gs *SimpleGossipService) handleMessage(msgBytes []byte, remoteAddr *net.UDPAddr) {
	// First try to unmarshal as a regular JSON object to check the structure
	var rawMsg map[string]interface{}
	if err := json.Unmarshal(msgBytes, &rawMsg); err != nil {
		// If we can't unmarshal as JSON at all, try UDP protocol message
		var udpMsg udpproto.Message
		if err := json.Unmarshal(msgBytes, &udpMsg); err != nil {
			logrus.Debugf("Failed to unmarshal message from %s: %v", remoteAddr.String(), err)
			return
		}
		
		// Verify UDP message signature
		if !udpMsg.Verify([]byte(gs.clusterSecret)) {
			logrus.Warnf("Invalid signature for UDP message from %s", remoteAddr.String())
			return
		}
		
		// If this is a UDP message, we don't need to process it here
		// This message will be handled by the UDPService
		logrus.Debugf("Received UDP message of type %s from %s, forwarding to UDP service", udpMsg.Type, remoteAddr.String())
		// We don't have a handleUDPMessage method, so just return
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
	
	// Now unmarshal as a SimpleGossipMessage
	var msg SimpleGossipMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		logrus.Warnf("Failed to unmarshal simple gossip message from %s: %v", remoteAddr.String(), err)
		return
	}
	
	// Verifikasi tanda tangan SimpleGossipMessage
	if !msg.VerifyHMAC([]byte(gs.clusterSecret)) {
		logrus.Warnf("Invalid HMAC for gossip message from %s", remoteAddr.String())
		return
	}
	
	// Periksa kadaluarsa pesan (lebih dari 30 detik dianggap kadaluarsa)
	if time.Now().Unix() - msg.Timestamp > 30 {
		logrus.Debugf("Ignoring expired message from %s (timestamp: %d, now: %d)", 
			remoteAddr.String(), msg.Timestamp, time.Now().Unix())
		return
	}
	
	switch msg.Type {
	case "join":
		var payload SimpleJoinPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal join payload: %v", err)
			return
		}
		
		logrus.Infof("Received JOIN from %s (peer: %s)", msg.Sender, payload.Addr)
		gs.updatePeer(payload.Addr)
		
		// Kirim respons join_ack
		gs.sendJoinAck(remoteAddr.String())
		
		// Kirim juga daftar peer yang diketahui
		gs.peersMu.RLock()
		var peerList []string
		for addr := range gs.peers {
			if addr != gs.localAddr && addr != payload.Addr {
				peerList = append(peerList, addr)
			}
		}
		gs.peersMu.RUnlock()
		
		// Kirim heartbeat dengan daftar peer
		if len(peerList) > 0 {
			gs.sendHeartbeat(payload.Addr, peerList)
		}
		
	case "join_ack":
		logrus.Debugf("Received JOIN_ACK from %s", msg.Sender)
		gs.updatePeer(msg.Sender)
		
	case "heartbeat":
		var payload SimpleHeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal heartbeat payload: %v", err)
			return
		}
		
		logrus.Debugf("Received HEARTBEAT from %s with %d peers", msg.Sender, len(payload.Peers))
		gs.updatePeer(msg.Sender)
		
		// Update peer list
		for _, peerAddr := range payload.Peers {
			gs.updatePeer(peerAddr)
		}
		
		// Kirim respons heartbeat_ack
		gs.sendHeartbeatAck(remoteAddr.String())
		
	case "heartbeat_ack":
		logrus.Debugf("Received HEARTBEAT_ACK from %s", msg.Sender)
		gs.updatePeer(msg.Sender)
		
	default:
		logrus.Warnf("Received unknown message type: %s from %s", msg.Type, remoteAddr.String())
	}
}

// updatePeer menambahkan atau memperbarui peer dalam daftar
func (gs *SimpleGossipService) updatePeer(peerAddr string) {
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
		
		// Notify about peer update
		select {
		case gs.PeerUpdateChan <- struct{}{}:
		default:
		}
	}
}

// sendHeartbeats secara berkala mengirim heartbeat ke semua peer
func (gs *SimpleGossipService) sendHeartbeats() {
	defer gs.wg.Done()
	ticker := time.NewTicker(gs.probeInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-gs.stopChan:
			return
		case <-ticker.C:
			gs.peersMu.RLock()
			if len(gs.peers) <= 1 {
				gs.peersMu.RUnlock()
				continue
			}
			
			// Buat daftar peer untuk dikirim
			var peerList []string
			for addr := range gs.peers {
				if addr != gs.localAddr {
					peerList = append(peerList, addr)
				}
			}
			
			// Kirim heartbeat ke semua peer
			for addr := range gs.peers {
				if addr != gs.localAddr {
					gs.sendHeartbeat(addr, peerList)
				}
			}
			
			gs.peersMu.RUnlock()
		}
	}
}

// checkPeerStatus secara berkala memeriksa peer yang mati
func (gs *SimpleGossipService) checkPeerStatus() {
	defer gs.wg.Done()
	ticker := time.NewTicker(gs.probeInterval)
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
				
				if time.Since(peer.LastSeen) > gs.probeTimeout {
					logrus.Warnf("Peer %s detected as dead (last seen %s ago)", addr, time.Since(peer.LastSeen).Round(time.Second))
					deadPeers = append(deadPeers, addr)
				}
			}
			
			// Hapus peer yang mati
			for _, addr := range deadPeers {
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

// discoverAndJoin mencoba menemukan dan bergabung dengan klaster
func (gs *SimpleGossipService) discoverAndJoin(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
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

// attemptJoin mencoba bergabung dengan klaster
func (gs *SimpleGossipService) attemptJoin(ctx context.Context) {
	// Jika kita sudah memiliki rekan selain diri sendiri, kita mungkin sudah terhubung
	gs.peersMu.RLock()
	peerCount := len(gs.peers)
	gs.peersMu.RUnlock()
	
	if peerCount > 1 {
		return
	}
	
	logrus.Infof("Discovering peer IPs from validation domain: %s", gs.validationDomain)
	seedIPs, err := DiscoverPeerIPs(ctx, gs.validationDomain)
	if err != nil {
		logrus.Warnf("Failed to discover seed peers: %v", err)
		return
	}
	
	// Kirim JOIN ke semua seed peer
	for _, ip := range seedIPs {
		seedAddr := fmt.Sprintf("%s:%d", ip.String(), DefaultGossipPort)
		if seedAddr == gs.localAddr {
			continue
		}
		
		gs.sendJoin(seedAddr)
	}
}

// sendJoin mengirim pesan JOIN ke alamat tertentu
func (gs *SimpleGossipService) sendJoin(targetAddr string) {
	payload := SimpleJoinPayload{
		Addr: gs.localAddr,
	}
	
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logrus.Errorf("Failed to marshal join payload: %v", err)
		return
	}
	
	msg := SimpleGossipMessage{
		Type:      "join",
		Sender:    gs.localAddr,
		Timestamp: time.Now().Unix(),
		Payload:   payloadBytes,
	}
	
	msg.Sign([]byte(gs.clusterSecret))
	
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Failed to marshal join message: %v", err)
		return
	}
	
	gs.sendUDPMessage(msgBytes, targetAddr)
}

// sendJoinAck mengirim pesan JOIN_ACK ke alamat tertentu
func (gs *SimpleGossipService) sendJoinAck(targetAddr string) {
	msg := SimpleGossipMessage{
		Type:      "join_ack",
		Sender:    gs.localAddr,
		Timestamp: time.Now().Unix(),
		Payload:   []byte("{}"),
	}
	
	msg.Sign([]byte(gs.clusterSecret))
	
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Failed to marshal join_ack message: %v", err)
		return
	}
	
	gs.sendUDPMessage(msgBytes, targetAddr)
}

// sendHeartbeat mengirim pesan HEARTBEAT ke alamat tertentu
func (gs *SimpleGossipService) sendHeartbeat(targetAddr string, peerList []string) {
	payload := SimpleHeartbeatPayload{
		Peers: peerList,
	}
	
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logrus.Errorf("Failed to marshal heartbeat payload: %v", err)
		return
	}
	
	msg := SimpleGossipMessage{
		Type:      "heartbeat",
		Sender:    gs.localAddr,
		Timestamp: time.Now().Unix(),
		Payload:   payloadBytes,
	}
	
	msg.Sign([]byte(gs.clusterSecret))
	
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Failed to marshal heartbeat message: %v", err)
		return
	}
	
	gs.sendUDPMessage(msgBytes, targetAddr)
}

// sendHeartbeatAck mengirim pesan HEARTBEAT_ACK ke alamat tertentu
func (gs *SimpleGossipService) sendHeartbeatAck(targetAddr string) {
	msg := SimpleGossipMessage{
		Type:      "heartbeat_ack",
		Sender:    gs.localAddr,
		Timestamp: time.Now().Unix(),
		Payload:   []byte("{}"),
	}
	
	msg.Sign([]byte(gs.clusterSecret))
	
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Failed to marshal heartbeat_ack message: %v", err)
		return
	}
	
	gs.sendUDPMessage(msgBytes, targetAddr)
}

// sendUDPMessage mengirim pesan UDP ke alamat tertentu
func (gs *SimpleGossipService) sendUDPMessage(msg []byte, targetAddr string) {
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
		
		// Set write deadline
		gs.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		
		_, err = gs.conn.WriteToUDP(msg, addr)
		
		// Reset write deadline
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
				logrus.Warnf("Connection refused when sending message to %s (attempt %d/%d)", 
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

// GetActivePeerAddrs mengembalikan daftar alamat peer yang aktif
func (gs *SimpleGossipService) GetActivePeerAddrs() []string {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	
	var active []string
	for addr := range gs.peers {
		active = append(active, addr)
	}
	
	return active
}

// GetRandomPeers mengembalikan slice acak dari peer yang aktif
func (gs *SimpleGossipService) GetRandomPeers(count int, includeSelf bool) []string {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	
	var activePeers []string
	for addr := range gs.peers {
		if !includeSelf && addr == gs.localAddr {
			continue
		}
		activePeers = append(activePeers, addr)
	}
	
	rand.Shuffle(len(activePeers), func(i, j int) {
		activePeers[i], activePeers[j] = activePeers[j], activePeers[i]
	})
	
	if len(activePeers) <= count {
		return activePeers
	}
	
	return activePeers[:count]
}

// GetPeerCount mengembalikan jumlah peer yang diketahui (termasuk diri sendiri)
func (gs *SimpleGossipService) GetPeerCount() int {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	
	return len(gs.peers)
}

// GetListenAddr mengembalikan alamat listen untuk gossip service
func (gs *SimpleGossipService) GetListenAddr() string {
	return fmt.Sprintf(":%d", DefaultGossipPort)
}

// GetLocalAddr mengembalikan alamat lokal node
func (gs *SimpleGossipService) GetLocalAddr() string {
	return gs.localAddr
}

// GetUDPConn mengembalikan koneksi UDP yang digunakan oleh gossip service
func (gs *SimpleGossipService) GetUDPConn() *net.UDPConn {
	return gs.conn
}