package server

import (
	"context"
	"fmt"
	"net"

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

// forwardToResponsibleNode mengirim request forwarding ke node yang bertanggung jawab
func (s *SSHServer) forwardToResponsibleNode(ctx context.Context, domain, responsibleNode, forwardID string, bindAddr string, bindPort uint32, originalAddr string) (bool, uint32, error) {
	// Buat payload untuk request forwarding
	forwardPayload := udpproto.ForwardPayload{
		Domain:       domain,
		BindAddr:     bindAddr,
		BindPort:     bindPort,
		ForwardID:    forwardID,
		OriginalAddr: originalAddr,
	}
	
	// Buat pesan
	msg, err := udpproto.NewMessage(udpproto.MessageTypeForward, s.LocalGossipAddr, forwardPayload)
	if err != nil {
		return false, 0, fmt.Errorf("gagal membuat pesan forward: %w", err)
	}
	
	// Dapatkan alamat UDP yang disukai untuk node yang bertanggung jawab
	targetAddr := s.getUDPAddressForNode(responsibleNode)
	logrus.Infof("Mengirim request forward ke node %s di alamat %s", responsibleNode, targetAddr)
	
	// Kirim pesan dan tunggu respons
	resp, err := s.UDPService.SendMessage(ctx, msg, targetAddr)
	if err != nil {
		return false, 0, fmt.Errorf("gagal mengirim pesan forward ke %s: %w", targetAddr, err)
	}
	
	// Parse respons
	respPayload, err := resp.GetForwardResponsePayload()
	if err != nil {
		return false, 0, fmt.Errorf("gagal parse respons forward: %w", err)
	}
	
	if !respPayload.Success {
		return false, 0, fmt.Errorf("forward gagal: %s", respPayload.Error)
	}
	
	return true, respPayload.Port, nil
}

// getUDPAddressForNode mendapatkan alamat UDP untuk node tertentu
func (s *SSHServer) getUDPAddressForNode(nodeAddr string) string {
	// Ekstrak host dari alamat node
	host, _, err := net.SplitHostPort(nodeAddr)
	if err != nil {
		// Jika gagal parse, gunakan alamat asli
		return fmt.Sprintf("%s:%d", nodeAddr, udpproto.DefaultUDPPort)
	}
	
	// Coba dapatkan port UDP dari node target
	targetPeer := s.GossipService.GetPeer(host)
	if targetPeer != nil && targetPeer.GossipPort > 0 {
		// Jika node target menggunakan port alternatif (8946), gunakan port tersebut
		return fmt.Sprintf("%s:%d", host, targetPeer.GossipPort + 1000)
	}
	
	// Jika tidak bisa mendapatkan informasi port dari peer, gunakan port alternatif (8946)
	// karena dari log terlihat semua node menggunakan port alternatif
	return fmt.Sprintf("%s:%d", host, udpproto.DefaultUDPPort + 1000)
}