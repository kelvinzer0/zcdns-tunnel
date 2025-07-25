package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/udpproto"
)

// handleForwardResponse menangani response dari forwarding request
func (s *SSHServer) handleForwardResponse(ctx context.Context, msg *udpproto.Message) (*udpproto.Message, error) {
	payload, err := msg.GetForwardResponsePayload()
	if err != nil {
		return nil, fmt.Errorf("gagal mendapatkan payload forward response: %w", err)
	}

	logFields := logrus.Fields{
		"forward_id": payload.ForwardID,
		"success":    payload.Success,
		"sender":     msg.Sender,
	}
	
	if payload.Port > 0 {
		logFields["port"] = payload.Port
	}
	
	if payload.Error != "" {
		logFields["error"] = payload.Error
	}
	
	if payload.Success {
		logrus.WithFields(logFields).Info("Menerima forward response sukses dari node lain")
	} else {
		logrus.WithFields(logFields).Warn("Menerima forward response gagal dari node lain")
	}

	// Cari client SSH yang mengirim request forward original
	s.mu.Lock()
	_, exists := s.forwardedClientConns[payload.ForwardID]
	if exists {
		// Hapus dari map karena sudah diproses
		delete(s.forwardedClientConns, payload.ForwardID)
	}
	s.mu.Unlock()
	
	if !exists {
		logrus.Warnf("Tidak ditemukan client SSH untuk forward_id: %s", payload.ForwardID)
	} else {
		logrus.Debugf("Client SSH ditemukan untuk forward_id: %s", payload.ForwardID)
		// Jika diperlukan, lakukan sesuatu dengan client
	}

	// Tidak perlu mengembalikan respons untuk pesan ini
	return nil, nil
}