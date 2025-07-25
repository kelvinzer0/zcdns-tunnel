package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/udpproto"
)

// handleForwardRequest menangani request forwarding dari node lain
func (s *SSHServer) handleForwardRequest(ctx context.Context, msg *udpproto.Message) (*udpproto.Message, error) {
	payload, err := msg.GetForwardPayload()
	if err != nil {
		return nil, fmt.Errorf("gagal mendapatkan payload forward: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"domain":       payload.Domain,
		"bind_addr":    payload.BindAddr,
		"bind_port":    payload.BindPort,
		"forward_id":   payload.ForwardID,
		"sender":       msg.Sender,
		"original_addr": payload.OriginalAddr,
	}).Info("Menerima request forward dari node lain")

	// Periksa apakah node ini bertanggung jawab untuk domain ini
	responsibleNode := s.ConsistentHash.Get(payload.Domain)
	if responsibleNode != s.LocalGossipAddr {
		errMsg := fmt.Sprintf("Node ini (%s) tidak bertanggung jawab untuk domain %s, node yang bertanggung jawab adalah %s",
			s.LocalGossipAddr, payload.Domain, responsibleNode)
		logrus.Warn(errMsg)
		
		// Buat respons error
		respPayload := udpproto.ForwardResponsePayload{
			ForwardID: payload.ForwardID,
			Success:   false,
			Error:     errMsg,
		}
		
		resp, err := udpproto.NewMessage(udpproto.MessageTypeForwardResponse, s.LocalGossipAddr, respPayload)
		if err != nil {
			return nil, err
		}
		
		return resp, nil
	}

	// Proses request forwarding seperti di handleTCPIPForward
	// Namun kita perlu memodifikasi logika untuk menangani request dari node lain
	
	// Untuk tujuan demo, kita akan membuat respons sukses sederhana
	// Di implementasi sebenarnya, Anda perlu mengimplementasikan logika forwarding lengkap
	
	respPayload := udpproto.ForwardResponsePayload{
		ForwardID: payload.ForwardID,
		Success:   true,
		Port:      payload.BindPort, // Gunakan port yang sama untuk demo
	}
	
	resp, err := udpproto.NewMessage(udpproto.MessageTypeForwardResponse, s.LocalGossipAddr, respPayload)
	if err != nil {
		return nil, err
	}
	
	return resp, nil
}

