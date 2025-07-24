package gossip

// MessageType mendefinisikan jenis pesan gossip.
type MessageType string

const (
	MessageTypeJoin     MessageType = "join"
	MessageTypeHeartbeat MessageType = "heartbeat"
	MessageTypeSync     MessageType = "sync" // Untuk pertukaran daftar peer
)

// GossipMessage adalah struktur dasar untuk semua pesan gossip.
type GossipMessage struct {
	Type    MessageType `json:"type"`
	Sender  string      `json:"sender"` // IP:Port dari pengirim
	Payload []byte      `json:"payload,omitempty"`
}

// JoinPayload dikirim ketika node baru bergabung.
type JoinPayload struct {
	NewPeer string `json:"new_peer"` // IP:Port dari node yang baru bergabung
}

// HeartbeatPayload dikirim secara berkala oleh node aktif.
type HeartbeatPayload struct {
	// Mungkin berisi informasi tambahan di masa depan,
	// seperti versi state atau subset peer yang diketahui.
	KnownPeers []string `json:"known_peers,omitempty"` // Subset peer yang diketahui pengirim
}

// SyncPayload berisi daftar peer yang diketahui.
type SyncPayload struct {
	Peers []string `json:"peers"` // Daftar lengkap peer yang diketahui pengirim
}
