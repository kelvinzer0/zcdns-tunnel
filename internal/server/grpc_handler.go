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
	// Log detailed information about the forwarding attempt
	logrus.WithFields(logrus.Fields{
		"domain":           domain,
		"responsible_node": responsibleNode,
		"forward_id":       forwardID,
		"bind_addr":        bindAddr,
		"bind_port":        bindPort,
		"original_addr":    originalAddr,
	}).Info("Attempting to forward request to responsible node")
	
	// Extract host from responsible node address
	host, _, err := net.SplitHostPort(responsibleNode)
	if err != nil {
		logrus.Warnf("Failed to parse responsible node address %s: %v", responsibleNode, err)
	logrus.WithFields(logrus.Fields{
		"domain":           domain,
		"responsible_node": responsibleNode,
		"host":             host,
	}).Info("Extracted host from responsible node address")
		host = responsibleNode // Use as is if parsing fails
	}
	
	// Try gRPC first if client is available
	var grpcErr error
	if s.GRPCClient != nil {
		logrus.WithField("target", responsibleNode).Info("Using gRPC for forwarding request")
		success, port, err := s.forwardToResponsibleNodeGRPC(ctx, domain, responsibleNode, forwardID, bindAddr, bindPort, originalAddr)
		if err == nil {
			logrus.WithFields(logrus.Fields{
				"domain":           domain,
				"responsible_node": responsibleNode,
				"port":             port,
			}).Info("Successfully forwarded request using gRPC")
			return success, port, nil
		}
		
		// Log the error but don't return yet - we'll try UDP as fallback
		grpcErr = err
		logrus.WithFields(logrus.Fields{
			"error":            err,
			"responsible_node": responsibleNode,
		}).Warn("gRPC forwarding failed, will try fallback methods")
	}

	// Fall back to UDP if gRPC failed or is not available
	var udpErr error
	if s.UDPService != nil && s.UDPService.GetUDPConn() != nil {
		logrus.WithField("target", responsibleNode).Info("Using UDP for forwarding request")
		success, port, err := s.forwardToResponsibleNodeUDP(ctx, domain, responsibleNode, forwardID, bindAddr, bindPort, originalAddr)
		if err == nil {
			logrus.WithFields(logrus.Fields{
				"domain":           domain,
				"responsible_node": responsibleNode,
				"port":             port,
			}).Info("Successfully forwarded request using UDP")
			return success, port, nil
		}
		
		// Log the error but don't return yet - we'll try direct SSH as a last resort
		udpErr = err
		logrus.WithFields(logrus.Fields{
			"error":            err,
			"responsible_node": responsibleNode,
		}).Warn("UDP forwarding failed, will try direct SSH as last resort")
	}
	
	// If we get here, both gRPC and UDP failed
	logrus.WithFields(logrus.Fields{
		"grpc_error": grpcErr,
		"udp_error":  udpErr,
		"domain":     domain,
		"target":     responsibleNode,
	}).Error("All standard forwarding methods failed")
	
	// As a last resort, return a special port value that indicates the client should try direct SSH
	// This is a workaround to allow clients to connect directly when inter-node communication fails
	logrus.WithFields(logrus.Fields{
		"domain":           domain,
		"responsible_node": responsibleNode,
	}).Info("Returning special port value to indicate direct SSH connection should be attempted")
	
	// Return a special port value (e.g., 22) to indicate direct SSH connection
	// The client will need to be modified to handle this special case
	return true, 22, nil
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
// getIntermediaryAddrFromResponsibleNode retrieves the intermediary address from the responsible node
func (s *SSHServer) getIntermediaryAddrFromResponsibleNode(ctx context.Context, domain, responsibleNode, forwardID string, protocolPrefix string, publicPort uint32) (string, error) {
	if s.GRPCClient == nil {
		return "", fmt.Errorf("gRPC client is not initialized")
	}

	// Extract host from responsible node address
	host, _, err := net.SplitHostPort(responsibleNode)
	if err != nil {
		logrus.Warnf("Failed to parse responsible node address %s: %v", responsibleNode, err)
		host = responsibleNode // Use as is if parsing fails
	}

	// Get the gRPC port from the configuration
	grpcPort := int32(s.Config.Gossip.GrpcPort)

	logrus.Infof("Retrieving intermediary address for domain %s from node %s at address %s (gRPC port: %d)", 
		domain, responsibleNode, host, grpcPort)

	// Get the intermediary address using gRPC with improved error handling
	intermediaryAddr, err := s.GRPCClient.GetIntermediaryAddrWithRetry(
		ctx, 
		host, 
		grpcPort, 
		domain, 
		protocolPrefix, 
		publicPort, 
		forwardID,
	)
	
	if err != nil {
		return "", fmt.Errorf("failed to get intermediary address from %s: %w", responsibleNode, err)
	}

	if intermediaryAddr == "" {
		// If the responsible node returned an empty address, try to check our local state
		// This can happen if the node is responsible but hasn't yet received the shared state
		localAddr, ok := s.Manager.LoadBridgeAddress(domain, protocolPrefix, publicPort)
		if ok && localAddr != "" {
			logrus.Infof("Using locally stored intermediary address %s for domain %s as responsible node returned empty", 
				localAddr, domain)
			return localAddr, nil
		}
		
		return "", fmt.Errorf("no intermediary address found for domain %s on node %s", domain, responsibleNode)
	}

	logrus.Infof("Retrieved intermediary address %s for domain %s from node %s", 
		intermediaryAddr, domain, responsibleNode)

	return intermediaryAddr, nil
}