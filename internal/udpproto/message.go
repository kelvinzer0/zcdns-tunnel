package udpproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"
	
	"github.com/sirupsen/logrus"
)

const (
	// MessageTypeForward adalah tipe pesan untuk request forwarding
	MessageTypeForward = "forward"
	// MessageTypeForwardResponse adalah tipe pesan untuk response forwarding
	MessageTypeForwardResponse = "forward_response"
	// MessageTypeHeartbeat adalah tipe pesan untuk heartbeat
	MessageTypeHeartbeat = "heartbeat"
	// MessageTypeHeartbeatResponse adalah tipe pesan untuk response heartbeat
	MessageTypeHeartbeatResponse = "heartbeat_response"
)

// Message adalah struktur dasar untuk semua pesan protokol UDP kustom
type Message struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Sender    string          `json:"sender"`
	Payload   json.RawMessage `json:"payload"`
	HMAC      []byte          `json:"hmac"`
}

// ForwardPayload adalah payload untuk request forwarding
type ForwardPayload struct {
	Domain       string `json:"domain"`
	BindAddr     string `json:"bind_addr"`
	BindPort     uint32 `json:"bind_port"`
	ForwardID    string `json:"forward_id"`
	OriginalAddr string `json:"original_addr"`
}

// ForwardResponsePayload adalah payload untuk response forwarding
type ForwardResponsePayload struct {
	ForwardID string `json:"forward_id"`
	Success   bool   `json:"success"`
	Port      uint32 `json:"port,omitempty"`
	Error     string `json:"error,omitempty"`
}

// HeartbeatPayload adalah payload untuk heartbeat
type HeartbeatPayload struct {
	KnownPeers []string `json:"known_peers,omitempty"`
	GossipPort int      `json:"gossip_port"`
}

// HeartbeatResponsePayload adalah payload untuk response heartbeat
type HeartbeatResponsePayload struct {
	Status string `json:"status"`
}

// NewMessage membuat pesan baru dengan tipe dan payload tertentu
func NewMessage(msgType string, sender string, payload interface{}) (*Message, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &Message{
		Type:      msgType,
		Timestamp: time.Now().Unix(),
		Sender:    sender,
		Payload:   payloadBytes,
	}, nil
}

// Sign menandatangani pesan dengan shared secret
func (m *Message) Sign(secret []byte) error {
	// Reset HMAC sebelum menandatangani
	m.HMAC = nil

	// Jika secret kosong, tidak perlu menandatangani
	if len(secret) == 0 {
		logrus.Debug("Secret kosong, pesan tidak akan ditandatangani")
		return nil
	}

	// Serialize pesan tanpa HMAC
	msgBytes, err := json.Marshal(m)
	if err != nil {
		return err
	}

	// Hitung HMAC
	h := hmac.New(sha256.New, secret)
	h.Write(msgBytes)
	m.HMAC = h.Sum(nil)

	return nil
}

// Verify memverifikasi tanda tangan pesan
func (m *Message) Verify(secret []byte) bool {
	// Simpan HMAC asli
	originalHMAC := m.HMAC
	
	// Jika tidak ada HMAC dan secret kosong, anggap valid
	if len(originalHMAC) == 0 && len(secret) == 0 {
		logrus.Debug("Pesan tanpa HMAC dan secret kosong, dianggap valid")
		return true
	}
	
	// Jika ada HMAC tapi secret kosong, anggap tidak valid
	if len(originalHMAC) > 0 && len(secret) == 0 {
		logrus.Debug("Pesan dengan HMAC tapi secret kosong, dianggap tidak valid")
		return false
	}
	
	// Jika tidak ada HMAC tapi ada secret, anggap tidak valid
	if len(originalHMAC) == 0 && len(secret) > 0 {
		logrus.Debug("Pesan tanpa HMAC tapi ada secret, dianggap tidak valid")
		return false
	}
	
	m.HMAC = nil

	// Serialize pesan tanpa HMAC
	msgBytes, err := json.Marshal(m)
	if err != nil {
		logrus.Warnf("Gagal serialize pesan untuk verifikasi: %v", err)
		return false
	}

	// Hitung HMAC
	h := hmac.New(sha256.New, secret)
	h.Write(msgBytes)
	calculatedHMAC := h.Sum(nil)

	// Kembalikan HMAC asli
	m.HMAC = originalHMAC

	// Log untuk debugging jika verifikasi gagal
	if !hmac.Equal(calculatedHMAC, originalHMAC) {
		logrus.Debugf("Verifikasi tanda tangan gagal: secret length=%d, original HMAC length=%d, calculated HMAC length=%d", 
			len(secret), len(originalHMAC), len(calculatedHMAC))
	}

	// Bandingkan HMAC
	return hmac.Equal(calculatedHMAC, originalHMAC)
}

// ParseMessage mem-parse pesan dari byte
func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// GetForwardPayload mengambil payload forward dari pesan
func (m *Message) GetForwardPayload() (*ForwardPayload, error) {
	if m.Type != MessageTypeForward {
		return nil, errors.New("bukan pesan forward")
	}

	var payload ForwardPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

// GetForwardResponsePayload mengambil payload forward response dari pesan
func (m *Message) GetForwardResponsePayload() (*ForwardResponsePayload, error) {
	if m.Type != MessageTypeForwardResponse {
		return nil, errors.New("bukan pesan forward response")
	}

	var payload ForwardResponsePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

// GetHeartbeatPayload mengambil payload heartbeat dari pesan
func (m *Message) GetHeartbeatPayload() (*HeartbeatPayload, error) {
	if m.Type != MessageTypeHeartbeat {
		return nil, errors.New("bukan pesan heartbeat")
	}

	var payload HeartbeatPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

// GetHeartbeatResponsePayload mengambil payload heartbeat response dari pesan
func (m *Message) GetHeartbeatResponsePayload() (*HeartbeatResponsePayload, error) {
	if m.Type != MessageTypeHeartbeatResponse {
		return nil, errors.New("bukan pesan heartbeat response")
	}

	var payload HeartbeatResponsePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}