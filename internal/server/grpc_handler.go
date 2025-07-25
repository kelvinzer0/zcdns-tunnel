package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/udpproto"
)

// forwardToResponsibleNodeGRPC forwards a request to the responsible node using gRPC
func (s *SSHServer) forwardToResponsibleNodeGRPC(ctx context.Context, domain, responsibleNode, forwardID string, bindAddr string, bindPort uint32, originalAddr string) (bool, uint32, error) {
	if s.GRPCClient == nil {
		return false, 0, fmt.Errorf("gRPC client is not initialized")
	}

	// Extract host from responsible node address
	host, _, err := net.SplitHostPort(responsibleNode)
	if err != nil {
		logrus.Warnf("Failed to parse responsible node address %s: %v", responsibleNode, err)
		host = responsibleNode // Use as is if parsing fails
	}

	// Get the gRPC port from the configuration
	grpcPort := int32(s.Config.Gossip.GrpcPort)

	logrus.Infof("Sending forward request to node %s at address %s (gRPC port: %d)", 
		responsibleNode, host, grpcPort)

	// Forward the request using gRPC
	resp, err := s.GRPCClient.ForwardRequestWithRetry(
		ctx, 
		host, 
		grpcPort, 
		domain, 
		bindAddr, 
		bindPort, 
		forwardID, 
		originalAddr,
	)
	
	if err != nil {
		return false, 0, fmt.Errorf("failed to forward request to %s: %w", responsibleNode, err)
	}

	if !resp.Success {
		return false, 0, fmt.Errorf("forward failed: %s", resp.Error)
	}

	return true, resp.Port, nil
}

// forwardToResponsibleNode is the main method for forwarding requests
// It tries to use gRPC if available, and falls back to UDP if needed
func (s *SSHServer) forwardToResponsibleNode(ctx context.Context, domain, responsibleNode, forwardID string, bindAddr string, bindPort uint32, originalAddr string) (bool, uint32, error) {
	// Try gRPC first if client is available
	if s.GRPCClient != nil {
		logrus.Debug("Using gRPC for forwarding request")
		success, port, err := s.forwardToResponsibleNodeGRPC(ctx, domain, responsibleNode, forwardID, bindAddr, bindPort, originalAddr)
		if err == nil {
			return success, port, nil
		}
		
		// Log the error but don't return yet - we'll try UDP as fallback
		logrus.Warnf("gRPC forwarding failed: %v, falling back to UDP", err)
	}

	// Fall back to UDP if gRPC failed or is not available
	if s.UDPService != nil && s.UDPService.GetUDPConn() != nil {
		logrus.Debug("Using UDP for forwarding request")
		return s.forwardToResponsibleNodeUDP(ctx, domain, responsibleNode, forwardID, bindAddr, bindPort, originalAddr)
	}

	// If we get here, both gRPC and UDP are unavailable
	return false, 0, fmt.Errorf("no communication method available for forwarding request")
}

// forwardToResponsibleNodeUDP forwards a request to the responsible node using UDP
// This is the original implementation, renamed for clarity
func (s *SSHServer) forwardToResponsibleNodeUDP(ctx context.Context, domain, responsibleNode, forwardID string, bindAddr string, bindPort uint32, originalAddr string) (bool, uint32, error) {
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
	
	// Extract host from responsible node address
	host, _, err := net.SplitHostPort(responsibleNode)
	if err != nil {
		logrus.Warnf("Failed to parse responsible node address %s: %v", responsibleNode, err)
		host = responsibleNode // Use as is if parsing fails
	}
	
	// Explicitly use port 7946 (DefaultUDPPort) for UDP communication
	targetAddr := fmt.Sprintf("%s:%d", host, udpproto.DefaultUDPPort)
	logrus.Infof("Mengirim request forward ke node %s di alamat %s (UDP port: %d)", 
		responsibleNode, targetAddr, udpproto.DefaultUDPPort)
	
	// Implementasi retry untuk mengatasi timeout dan connection refused
	maxRetries := 3
	var resp *udpproto.Message
	var respErr error
	
	for retry := 0; retry < maxRetries; retry++ {
		// Jika ini bukan percobaan pertama, log retry dan tunggu sebentar
		if retry > 0 {
			backoffTime := time.Duration(retry) * 500 * time.Millisecond
			logrus.Infof("Percobaan ke-%d mengirim request forward ke %s (backoff: %v)", retry+1, targetAddr, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Kirim pesan dan tunggu respons dengan timeout yang meningkat
		timeoutDuration := time.Duration(retry+1) * udpproto.DefaultMessageTimeout
		ctxWithTimeout, cancel := context.WithTimeout(ctx, timeoutDuration)
		
		resp, respErr = s.UDPService.SendMessage(ctxWithTimeout, msg, targetAddr)
		cancel()
		
		// Jika berhasil, keluar dari loop
		if respErr == nil {
			break
		}
		
		// Log error dan tentukan apakah perlu retry
		if strings.Contains(respErr.Error(), "timeout") {
			logrus.Warnf("Timeout mengirim pesan ke %s (percobaan %d/%d): %v", targetAddr, retry+1, maxRetries, respErr)
		} else if strings.Contains(respErr.Error(), "connection refused") {
			logrus.Warnf("Koneksi ditolak oleh %s (percobaan %d/%d): %v", targetAddr, retry+1, maxRetries, respErr)
		} else {
			logrus.Errorf("Error mengirim pesan ke %s (percobaan %d/%d): %v", targetAddr, retry+1, maxRetries, respErr)
		}
		
		// Jika ini adalah percobaan terakhir, return error
		if retry == maxRetries-1 {
			return false, 0, fmt.Errorf("gagal mengirim pesan forward ke %s setelah %d percobaan: %w", targetAddr, maxRetries, respErr)
		}
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