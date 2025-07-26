package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"zcdns-tunnel/internal/config"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// GRPCClient implements the gRPC client for node communication
type GRPCClient struct {
	config    config.GossipConfig
	localAddr string
}

// NewGRPCClient creates a new gRPC client instance
func NewGRPCClient(cfg config.GossipConfig, localAddr string) *GRPCClient {
	return &GRPCClient{
		config:    cfg,
		localAddr: localAddr,
	}
}

// dialPeer creates a gRPC connection to a peer with improved error handling and diagnostics
func (c *GRPCClient) dialPeer(addr string, port int32) (*grpc.ClientConn, error) {
	target := fmt.Sprintf("%s:%d", addr, port)
	logrus.Infof("Attempting to dial gRPC peer at %s", target)
	
	// First, check if the target is reachable with a simple TCP connection
	// This helps diagnose network connectivity issues early
	dialer := net.Dialer{Timeout: 5 * time.Second}
	testConn, err := dialer.Dial("tcp", target)
	if err != nil {
		// Log detailed error information for network diagnostics
		logrus.WithFields(logrus.Fields{
			"target": target,
			"error":  err,
		}).Error("Failed basic TCP connectivity test to peer - check firewall rules and network connectivity")
		
		// Check if this is a DNS resolution issue
		if dnsErr, ok := err.(*net.DNSError); ok {
			logrus.WithFields(logrus.Fields{
				"target":  target,
				"dns_err": dnsErr,
			}).Error("DNS resolution failed for peer")
		}
		
		// Check if this is a timeout issue
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logrus.WithFields(logrus.Fields{
				"target": target,
			}).Error("Connection timed out - peer may be down or blocked by firewall")
		}
		
		return nil, fmt.Errorf("failed basic TCP connectivity test to %s: %w", target, err)
	}
	testConn.Close() // Close the test connection
	logrus.Infof("Basic TCP connectivity to %s confirmed", target)
	
	// Configure dial options with more robust settings
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		// Increase timeout to 15 seconds for more reliable connections
		grpc.WithTimeout(15 * time.Second),
		// Add backoff configuration for retries
		grpc.WithBackoffMaxDelay(5 * time.Second),
	}
	
	// Add TLS if configured
	if c.config.UseTLS {
		// In a production environment, you would want to use a proper TLS configuration
		// with certificate verification. For simplicity, we're using InsecureSkipVerify here.
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
		opts = append(opts, grpc.WithTransportCredentials(creds))
		logrus.Debugf("Using TLS for gRPC connection to %s", target)
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logrus.Debugf("Using insecure credentials for gRPC connection to %s", target)
	}
	
	// Add keepalive parameters with more aggressive settings for better connection stability
	kaParams := keepalive.ClientParameters{
		Time:                3 * time.Second,  // More frequent keepalive pings (was 5s)
		Timeout:             2 * time.Second,
		PermitWithoutStream: true,
	}
	opts = append(opts, grpc.WithKeepaliveParams(kaParams))
	
	return grpc.Dial(target, opts...)
}

// JoinCluster sends a join request to a peer
func (c *GRPCClient) JoinCluster(ctx context.Context, peerAddr string, peerPort int32) ([]*pb.Node, error) {
	conn, err := c.dialPeer(peerAddr, peerPort)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer %s:%d: %w", peerAddr, peerPort, err)
	}
	defer conn.Close()
	
	client := pb.NewGossipServiceClient(conn)
	
	// Create the join request
	req := &pb.JoinRequest{
		NewNode: &pb.Node{
			Address:    c.localAddr,
			GossipPort: int32(c.config.GrpcPort),
		},
	}
	
	// Send the join request
	resp, err := client.Join(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to join cluster via %s:%d: %w", peerAddr, peerPort, err)
	}
	
	if !resp.Success {
		return nil, fmt.Errorf("join request rejected by %s:%d: %s", peerAddr, peerPort, resp.Error)
	}
	
	return resp.KnownPeers, nil
}

// SendHeartbeat sends a heartbeat to a peer
func (c *GRPCClient) SendHeartbeat(ctx context.Context, peerAddr string, peerPort int32, knownPeers []*pb.Node) ([]*pb.Node, error) {
	conn, err := c.dialPeer(peerAddr, peerPort)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer %s:%d: %w", peerAddr, peerPort, err)
	}
	defer conn.Close()
	
	client := pb.NewGossipServiceClient(conn)
	
	// Create the heartbeat request
	req := &pb.HeartbeatRequest{
		Sender: &pb.Node{
			Address:    c.localAddr,
			GossipPort: int32(c.config.GrpcPort),
		},
		KnownPeers: knownPeers,
	}
	
	// Send the heartbeat
	resp, err := client.Heartbeat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send heartbeat to %s:%d: %w", peerAddr, peerPort, err)
	}
	
	if !resp.Success {
		return nil, fmt.Errorf("heartbeat rejected by %s:%d: %s", peerAddr, peerPort, resp.Error)
	}
	
	return resp.KnownPeers, nil
}

// ForwardRequest forwards a request to a peer
func (c *GRPCClient) ForwardRequest(ctx context.Context, peerAddr string, peerPort int32, domain, bindAddr string, bindPort uint32, forwardID, originalAddr string) (*pb.ForwardResponseMessage, error) {
	conn, err := c.dialPeer(peerAddr, peerPort)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer %s:%d: %w", peerAddr, peerPort, err)
	}
	defer conn.Close()
	
	client := pb.NewGossipServiceClient(conn)
	
	// Create the forward request
	req := &pb.ForwardRequestMessage{
		Domain:       domain,
		BindAddr:     bindAddr,
		BindPort:     bindPort,
		ForwardId:    forwardID,
		OriginalAddr: originalAddr,
		Sender: &pb.Node{
			Address:    c.localAddr,
			GossipPort: int32(c.config.GrpcPort),
		},
	}
	
	// Use the timeout from the parent context
	// The parent context should already have an appropriate timeout
	
	// Send the forward request
	resp, err := client.ForwardRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request to %s:%d: %w", peerAddr, peerPort, err)
	}
	
	return resp, nil
}

// ForwardRequestWithRetry forwards a request to a peer with enhanced retry logic
func (c *GRPCClient) ForwardRequestWithRetry(ctx context.Context, peerAddr string, peerPort int32, domain, bindAddr string, bindPort uint32, forwardID, originalAddr string) (*pb.ForwardResponseMessage, error) {
	var lastErr error
	maxRetries := 8  // Increased from 5 to 8 for more persistence
	
	// Log the start of the retry process
	logrus.Infof("Starting to forward request to %s:%d for domain %s with up to %d retries", 
		peerAddr, peerPort, domain, maxRetries)
	
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries with exponential backoff
		if retry > 0 {
			backoffTime := time.Duration(1<<uint(retry-1)) * 500 * time.Millisecond
			if backoffTime > 5*time.Second {
				backoffTime = 5 * time.Second // Cap at 5 seconds
			}
			logrus.Infof("Retry %d/%d forwarding request to %s:%d for domain %s after %v", 
				retry+1, maxRetries, peerAddr, peerPort, domain, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Create a new context with increasing timeout for each retry
		timeoutDuration := 10 * time.Second * time.Duration(retry+1) // Start with 10s and increase
		if timeoutDuration > 30*time.Second {
			timeoutDuration = 30 * time.Second // Cap at 30 seconds
		}
		
		reqCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
		
		// Log detailed information about this attempt
		logrus.WithFields(logrus.Fields{
			"retry":      retry + 1,
			"max_retries": maxRetries,
			"timeout":    timeoutDuration,
			"peer_addr":  peerAddr,
			"peer_port":  peerPort,
			"domain":     domain,
		}).Info("Attempting to forward request")
		
		resp, err := c.ForwardRequest(reqCtx, peerAddr, peerPort, domain, bindAddr, bindPort, forwardID, originalAddr)
		cancel()
		
		if err == nil {
			logrus.WithFields(logrus.Fields{
				"peer_addr": peerAddr,
				"peer_port": peerPort,
				"domain":    domain,
				"success":   resp.Success,
				"port":      resp.Port,
			}).Info("Successfully forwarded request")
			return resp, nil
		}
		
		lastErr = err
		logrus.WithFields(logrus.Fields{
			"peer_addr":  peerAddr,
			"peer_port":  peerPort,
			"domain":     domain,
			"retry":      retry + 1,
			"max_retries": maxRetries,
			"error":      err,
		}).Warn("Failed to forward request")
		
		// Check if we should abort early based on the error type
		if strings.Contains(err.Error(), "connection refused") {
			// If connection refused, the peer might be down, so we might want to retry
			logrus.Warn("Connection refused, will retry with exponential backoff")
		} else if strings.Contains(err.Error(), "deadline exceeded") {
			// If deadline exceeded, the peer might be overloaded, so we might want to retry
			logrus.Warn("Request timed out, will retry with increased timeout")
		} else if strings.Contains(err.Error(), "transport is closing") || 
			   strings.Contains(err.Error(), "connection closed") {
			// If connection is closing or closed, we should reconnect
			logrus.Warn("Connection is closing or closed, will attempt to reconnect")
		}
	}
	
	return nil, fmt.Errorf("failed to forward request after %d attempts: %w", maxRetries, lastErr)
}
// ShareIntermediaryAddr shares an intermediary address with a peer
func (c *GRPCClient) ShareIntermediaryAddr(ctx context.Context, peerAddr string, peerPort int32, domain, protocolPrefix string, publicPort uint32, intermediaryAddr, forwardID string) (bool, error) {
	conn, err := c.dialPeer(peerAddr, peerPort)
	if err != nil {
		return false, fmt.Errorf("failed to dial peer %s:%d: %w", peerAddr, peerPort, err)
	}
	defer conn.Close()
	
	client := pb.NewGossipServiceClient(conn)
	
	// Create the share intermediary address request
	req := &pb.IntermediaryAddrMessage{
		Domain:          domain,
		ProtocolPrefix:  protocolPrefix,
		PublicPort:      publicPort,
		IntermediaryAddr: intermediaryAddr,
		ForwardId:       forwardID,
		Sender: &pb.Node{
			Address:    c.localAddr,
			GossipPort: int32(c.config.GrpcPort),
		},
	}
	
	// Send the share intermediary address request
	resp, err := client.ShareIntermediaryAddr(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to share intermediary address with %s:%d: %w", peerAddr, peerPort, err)
	}
	
	if !resp.Success {
		return false, fmt.Errorf("share intermediary address rejected by %s:%d: %s", peerAddr, peerPort, resp.Error)
	}
	
	return true, nil
}

// ShareIntermediaryAddrWithRetry shares an intermediary address with a peer with retry
func (c *GRPCClient) ShareIntermediaryAddrWithRetry(ctx context.Context, peerAddr string, peerPort int32, domain, protocolPrefix string, publicPort uint32, intermediaryAddr, forwardID string) (bool, error) {
	var lastErr error
	maxRetries := 5
	
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries with exponential backoff
		if retry > 0 {
			backoffTime := time.Duration(1<<uint(retry-1)) * 500 * time.Millisecond
			logrus.Infof("Retry %d/%d sharing intermediary address to %s:%d after %v", 
				retry+1, maxRetries, peerAddr, peerPort, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Create a new context with increasing timeout for each retry
		timeoutDuration := 5 * time.Second * time.Duration(retry+1)
		if timeoutDuration > 20*time.Second {
			timeoutDuration = 20 * time.Second // Cap at 20 seconds
		}
		
		reqCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
		success, err := c.ShareIntermediaryAddr(reqCtx, peerAddr, peerPort, domain, protocolPrefix, publicPort, intermediaryAddr, forwardID)
		cancel()
		
		if err == nil {
			return success, nil
		}
		
		lastErr = err
		logrus.Warnf("Failed to share intermediary address with %s:%d (attempt %d/%d): %v", 
			peerAddr, peerPort, retry+1, maxRetries, err)
	}
	
	return false, fmt.Errorf("failed to share intermediary address after %d attempts: %w", maxRetries, lastErr)
}

// GetIntermediaryAddr gets an intermediary address from a peer
func (c *GRPCClient) GetIntermediaryAddr(ctx context.Context, peerAddr string, peerPort int32, domain, protocolPrefix string, publicPort uint32, forwardID string) (string, error) {
	conn, err := c.dialPeer(peerAddr, peerPort)
	if err != nil {
		return "", fmt.Errorf("failed to dial peer %s:%d: %w", peerAddr, peerPort, err)
	}
	defer conn.Close()
	
	client := pb.NewGossipServiceClient(conn)
	
	// Create the get intermediary address request
	req := &pb.IntermediaryAddrRequest{
		Domain:         domain,
		ProtocolPrefix: protocolPrefix,
		PublicPort:     publicPort,
		ForwardId:      forwardID,
		Sender: &pb.Node{
			Address:    c.localAddr,
			GossipPort: int32(c.config.GrpcPort),
		},
	}
	
	// Send the get intermediary address request
	resp, err := client.GetIntermediaryAddr(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to get intermediary address from %s:%d: %w", peerAddr, peerPort, err)
	}
	
	return resp.IntermediaryAddr, nil
}

// GetIntermediaryAddrWithRetry gets an intermediary address from a peer with enhanced retry logic
func (c *GRPCClient) GetIntermediaryAddrWithRetry(ctx context.Context, peerAddr string, peerPort int32, domain, protocolPrefix string, publicPort uint32, forwardID string) (string, error) {
	var lastErr error
	maxRetries := 8 // Increased from 5 to 8
	
	// Log the start of the retry process
	logrus.Infof("Starting to get intermediary address from %s:%d for domain %s with up to %d retries", 
		peerAddr, peerPort, domain, maxRetries)
	
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries with exponential backoff
		if retry > 0 {
			backoffTime := time.Duration(1<<uint(retry-1)) * 500 * time.Millisecond
			if backoffTime > 5*time.Second {
				backoffTime = 5 * time.Second // Cap at 5 seconds
			}
			logrus.Infof("Retry %d/%d getting intermediary address from %s:%d for domain %s after %v", 
				retry+1, maxRetries, peerAddr, peerPort, domain, backoffTime)
			time.Sleep(backoffTime)
		}
		
		// Create a new context with increasing timeout for each retry
		timeoutDuration := 10 * time.Second * time.Duration(retry+1)
		if timeoutDuration > 30*time.Second {
			timeoutDuration = 30 * time.Second // Cap at 30 seconds
		}
		
		reqCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
		
		// Log detailed information about this attempt
		logrus.WithFields(logrus.Fields{
			"retry":          retry + 1,
			"max_retries":    maxRetries,
			"timeout":        timeoutDuration,
			"peer_addr":      peerAddr,
			"peer_port":      peerPort,
			"domain":         domain,
			"protocol_prefix": protocolPrefix,
			"public_port":    publicPort,
		}).Info("Attempting to get intermediary address")
		
		addr, err := c.GetIntermediaryAddr(reqCtx, peerAddr, peerPort, domain, protocolPrefix, publicPort, forwardID)
		cancel()
		
		if err == nil {
			if addr != "" {
				logrus.WithFields(logrus.Fields{
					"peer_addr":       peerAddr,
					"peer_port":       peerPort,
					"domain":          domain,
					"intermediary_addr": addr,
				}).Info("Successfully got intermediary address")
				return addr, nil
			} else {
				// If we got an empty address, log it but continue with retries
				logrus.WithFields(logrus.Fields{
					"peer_addr":    peerAddr,
					"peer_port":    peerPort,
					"domain":       domain,
					"retry":        retry + 1,
					"max_retries":  maxRetries,
				}).Warn("Got empty intermediary address, will retry")
				
				// Use a shorter backoff for empty responses
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}
		
		lastErr = err
		logrus.WithFields(logrus.Fields{
			"peer_addr":    peerAddr,
			"peer_port":    peerPort,
			"domain":       domain,
			"retry":        retry + 1,
			"max_retries":  maxRetries,
			"error":        err,
		}).Warn("Failed to get intermediary address")
		
		// Check if we should abort early based on the error type
		if strings.Contains(err.Error(), "connection refused") {
			// If connection refused, the peer might be down, so we might want to retry
			logrus.Warn("Connection refused, will retry with exponential backoff")
		} else if strings.Contains(err.Error(), "deadline exceeded") {
			// If deadline exceeded, the peer might be overloaded, so we might want to retry
			logrus.Warn("Request timed out, will retry with increased timeout")
		} else if strings.Contains(err.Error(), "transport is closing") || 
				 strings.Contains(err.Error(), "connection closed") {
			// If connection is closing or closed, we should reconnect
			logrus.Warn("Connection is closing or closed, will attempt to reconnect")
		}
	}
	
	if lastErr != nil {
		return "", fmt.Errorf("failed to get intermediary address after %d attempts: %w", maxRetries, lastErr)
	}
	
	return "", fmt.Errorf("failed to get intermediary address after %d attempts: empty response", maxRetries)
}