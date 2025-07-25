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

	logrus.WithFields(logrus.Fields{
		"forward_id": payload.ForwardID,
		"success":    payload.Success,
		"port":       payload.Port,
		"error":      payload.Error,
		"sender":     msg.Sender,
	}).Info("Menerima forward response dari node lain")

	// Tidak perlu mengembalikan respons untuk pesan ini
	return nil, nil
}