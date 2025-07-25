package gossip

// MessageType mendefinisikan jenis pesan gossip.
type MessageType string

const (
	MessageTypeJoin      MessageType = "join"
	MessageTypeHeartbeat MessageType = "heartbeat"
	MessageTypeSync      MessageType = "sync" // Untuk pertukaran daftar peer

	// Pesan untuk penemuan IP publik
	MessageTypeWhoAmI         MessageType = "whoami"
	MessageTypeWhoAmIResponse MessageType = "whoami_response"
)

// GossipMessage adalah struktur dasar untuk semua pesan gossip.
type GossipMessage struct {
	Type    MessageType `json:"type"`
	Sender  string      `json:"sender"` // IP:Port dari pengirim
	Payload []byte      `json:"payload,omitempty"`
}

// JoinPayload dikirim ketika node baru bergabung.
type JoinPayload struct {
	NewPeer      string `json:"new_peer"`       // IP:Port dari node yang baru bergabung
	SSHListenAddr string `json:"ssh_listen_addr"` // SSH listen address of the new peer
	GossipPort   int    `json:"gossip_port"`    // Gossip port for direct communication
}

// HeartbeatPayload dikirim secara berkala oleh node aktif.
type HeartbeatPayload struct {
	KnownPeers    []string `json:"known_peers,omitempty"` // Subset peer yang diketahui pengirim
	SSHListenAddr string   `json:"ssh_listen_addr"`       // SSH listen address of the sender
	GossipPort    int      `json:"gossip_port"`           // Gossip port for direct communication
}

// SyncPayload berisi daftar peer yang diketahui.
type SyncPayload struct {
	Peers []string `json:"peers"` // Daftar lengkap peer yang diketahui pengirim
}

// WhoAmIResponsePayload berisi alamat publik yang diamati dari pemohon.
type WhoAmIResponsePayload struct {
	PublicAddr string `json:"public_addr"`
}
