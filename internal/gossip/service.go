package gossip

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus" // Menggunakan logrus untuk logging
)

const (
	heartbeatInterval = 5 * time.Second
	peerTimeout       = 15 * time.Second // Jika peer tidak terlihat selama ini, anggap mati
	syncInterval      = 30 * time.Second // Interval untuk sinkronisasi daftar peer
	maxPeersToSend    = 5                // Maksimum peer yang dikirim dalam heartbeat/sync
)

// GossipService mengelola keanggotaan klaster menggunakan protokol gossip.
type GossipService struct {
	LocalAddr string // Alamat IP:Port lokal dari node ini

	peersMu sync.RWMutex
	peers   map[string]*Peer // map[Addr]Peer

	conn *net.UDPConn // Koneksi UDP untuk mengirim/menerima pesan

	stopChan chan struct{}
	wg       sync.WaitGroup

	PeerUpdateChan chan struct{} // Channel untuk memberi tahu perubahan peer
}

// NewGossipService membuat instance GossipService baru.
func NewGossipService(localAddr string) *GossipService {
	return &GossipService{
		LocalAddr: localAddr,
		peers:     make(map[string]*Peer),
		stopChan:  make(chan struct{}),
		PeerUpdateChan: make(chan struct{}, 1), // Buffered channel
	}
}

// Start memulai layanan gossip.
func (gs *GossipService) Start() error {
	addr, err := net.ResolveUDPAddr("udp", gs.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}
	gs.conn = conn
	logrus.Infof("Gossip service listening on %s", gs.LocalAddr)

	// Tambahkan diri sendiri ke daftar peer
	gs.peersMu.Lock()
	gs.peers[gs.LocalAddr] = NewPeer(gs.LocalAddr)
	gs.peersMu.Unlock()

	gs.wg.Add(3)
	go gs.listenForMessages()
	go gs.sendHeartbeats()
	go gs.checkPeerStatus()

	return nil
}

// Stop menghentikan layanan gossip.
func (gs *GossipService) Stop() {
	logrus.Info("Stopping gossip service...")
	close(gs.stopChan)
	gs.conn.Close() // Menutup koneksi UDP akan menghentikan listenForMessages
	gs.wg.Wait()
	logrus.Info("Gossip service stopped.")
}

// Join mencoba bergabung dengan klaster menggunakan seed peers.
func (gs *GossipService) Join(seedPeers []string) {
	joinPayload, _ := json.Marshal(JoinPayload{NewPeer: gs.LocalAddr})
	msg := GossipMessage{
		Type:    MessageTypeJoin,
		Sender:  gs.LocalAddr,
		Payload: joinPayload,
	}
	msgBytes, _ := json.Marshal(msg)

	for _, seed := range seedPeers {
		if seed == gs.LocalAddr {
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

	// Perbarui status pengirim (jika belum ada, tambahkan)
	gs.peersMu.Lock()
	if peer, ok := gs.peers[msg.Sender]; ok {
		peer.UpdateLastSeen()
	} else {
		logrus.Infof("Discovered new peer: %s", msg.Sender)
		gs.peers[msg.Sender] = NewPeer(msg.Sender)
		// Propagasi penemuan peer baru ke peer lain
		go gs.propagateNewPeer(msg.Sender)
		select {
		case gs.PeerUpdateChan <- struct{}{}:
		default:
		}
	}
	gs.peersMu.Unlock()

	switch msg.Type {
	case MessageTypeJoin:
		var payload JoinPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal JoinPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Infof("Received JOIN from %s (new peer: %s)", msg.Sender, payload.NewPeer)
		// Pastikan payload.NewPeer juga ditambahkan/diperbarui
		gs.peersMu.Lock()
		if peer, ok := gs.peers[payload.NewPeer]; ok {
			peer.UpdateLastSeen()
		} else {
			logrus.Infof("Discovered new peer from JOIN payload: %s", payload.NewPeer)
			gs.peers[payload.NewPeer] = NewPeer(payload.NewPeer)
			go gs.propagateNewPeer(payload.NewPeer)
		}
		gs.peersMu.Unlock()

	case MessageTypeHeartbeat:
		var payload HeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal HeartbeatPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received HEARTBEAT from %s. Known peers in payload: %v", msg.Sender, payload.KnownPeers)
		// Update local peer list based on known peers from heartbeat
		gs.peersMu.Lock()
		for _, knownPeerAddr := range payload.KnownPeers {
			if _, ok := gs.peers[knownPeerAddr]; !ok {
				logrus.Infof("Discovered new peer from HEARTBEAT payload: %s", knownPeerAddr)
				gs.peers[knownPeerAddr] = NewPeer(knownPeerAddr)
				go gs.propagateNewPeer(knownPeerAddr)
				select {
				case gs.PeerUpdateChan <- struct{}{}:
				default:
				}
			}
		}
		gs.peersMu.Unlock()

	case MessageTypeSync:
		var payload SyncPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			logrus.Warnf("Failed to unmarshal SyncPayload from %s: %v", remoteAddr.String(), err)
			return
		}
		logrus.Debugf("Received SYNC from %s. Full peer list: %v", msg.Sender, payload.Peers)
		gs.peersMu.Lock()
		for _, syncPeerAddr := range payload.Peers {
			if _, ok := gs.peers[syncPeerAddr]; !ok {
				logrus.Infof("Discovered new peer from SYNC payload: %s", syncPeerAddr)
				gs.peers[syncPeerAddr] = NewPeer(syncPeerAddr)
				go gs.propagateNewPeer(syncPeerAddr)
			}
		}
		gs.peersMu.Unlock()

	default:
		logrus.Warnf("Received unknown gossip message type: %s from %s", msg.Type, remoteAddr.String())
	}
}

// propagateNewPeer mengirim pesan JOIN untuk peer baru ke subset peer yang diketahui.
func (gs *GossipService) propagateNewPeer(newPeerAddr string) {
	joinPayload, _ := json.Marshal(JoinPayload{NewPeer: newPeerAddr})
	msg := GossipMessage{
		Type:    MessageTypeJoin,
		Sender:  gs.LocalAddr,
		Payload: joinPayload,
	}
	msgBytes, _ := json.Marshal(msg)

	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()

	// Kirim ke beberapa peer acak
	activePeers := gs.getActivePeerAddrs()
	rand.Shuffle(len(activePeers), func(i, j int) {
		activePeers[i], activePeers[j] = activePeers[j], activePeers[i]
	})

	count := 0
	for _, peerAddr := range activePeers {
		if peerAddr == gs.LocalAddr || peerAddr == newPeerAddr {
			continue
		}
		go gs.sendMessage(msgBytes, peerAddr)
		count++
		if count >= maxPeersToSend { // Batasi propagasi untuk menghindari banjir
			break
		}
	}
}

// sendHeartbeats secara berkala mengirim heartbeat ke peer acak.
func (gs *GossipService) sendHeartbeats() {
	defer gs.wg.Done()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gs.stopChan:
			return
		case <-ticker.C:
			gs.peersMu.RLock()
			activePeers := gs.getActivePeerAddrs()
			gs.peersMu.RUnlock()

			if len(activePeers) == 0 {
				logrus.Debug("No active peers to send heartbeats to.")
				continue
			}

			// Ambil subset peer untuk dikirim dalam heartbeat
			knownPeersInPayload := []string{}
			rand.Shuffle(len(activePeers), func(i, j int) {
				activePeers[i], activePeers[j] = activePeers[j], activePeers[i]
			})
			for i, peerAddr := range activePeers {
				if i >= maxPeersToSend {
					break
				}
				knownPeersInPayload = append(knownPeersInPayload, peerAddr)
			}

			heartbeatPayload, _ := json.Marshal(HeartbeatPayload{KnownPeers: knownPeersInPayload})
			msg := GossipMessage{
				Type:    MessageTypeHeartbeat,
				Sender:  gs.LocalAddr,
				Payload: heartbeatPayload,
			}
			msgBytes, _ := json.Marshal(msg)

			// Kirim heartbeat ke beberapa peer acak
			rand.Shuffle(len(activePeers), func(i, j int) {
				activePeers[i], activePeers[j] = activePeers[j], activePeers[i]
			})
			count := 0
			for _, peerAddr := range activePeers {
				if peerAddr == gs.LocalAddr {
					continue
				}
				go gs.sendMessage(msgBytes, peerAddr)
				count++
				if count >= maxPeersToSend {
					break
				}
			}
		}
	}
}

// checkPeerStatus secara berkala memeriksa peer yang mati.
func (gs *GossipService) checkPeerStatus() {
	defer gs.wg.Done()
	ticker := time.NewTicker(heartbeatInterval) // Periksa sesering heartbeat
	defer ticker.Stop()

	for {
		select {
		case <-gs.stopChan:
			return
		case <-ticker.C:
			gs.peersMu.Lock()
			for addr, peer := range gs.peers {
				if addr == gs.LocalAddr {
					continue
				}
				lastSeen, isAlive := peer.GetStatus()
				if isAlive && time.Since(lastSeen) > peerTimeout {
					peer.MarkDead()
					logrus.Warnf("Peer %s detected as dead (last seen %s ago)", addr, time.Since(lastSeen))
					select {
					case gs.PeerUpdateChan <- struct{}{}:
					default:
					}
					// TODO: Propagate "leave" message or more robust failure detection
				}
			}
			gs.peersMu.Unlock()
		}
	}
}

// GetActivePeerAddrs mengembalikan daftar alamat peer yang aktif.
func (gs *GossipService) GetActivePeerAddrs() []string {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()

	var active []string
	for addr, peer := range gs.peers {
		if peer.IsAlive {
			active = append(active, addr)
		}
	}
	return active
}

// GetPeerCount mengembalikan jumlah peer yang diketahui (termasuk diri sendiri).
func (gs *GossipService) GetPeerCount() int {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()
	return len(gs.peers)
}
