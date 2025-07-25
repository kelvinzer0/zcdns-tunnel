package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
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

// dialPeer creates a gRPC connection to a peer
func (c *GRPCClient) dialPeer(addr string, port int32) (*grpc.ClientConn, error) {
	target := fmt.Sprintf("%s:%d", addr, port)
	
	// Configure dial options
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTimeout(2 * time.Second),
	}
	
	// Add TLS if configured
	if c.config.UseTLS {
		// In a production environment, you would want to use a proper TLS configuration
		// with certificate verification. For simplicity, we're using InsecureSkipVerify here.
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	
	// Add keepalive parameters
	kaParams := keepalive.ClientParameters{
		Time:                10 * time.Second,
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
	
	// Set a timeout for the request
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	// Send the forward request
	resp, err := client.ForwardRequest(ctxWithTimeout, req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request to %s:%d: %w", peerAddr, peerPort, err)
	}
	
	return resp, nil
}

// ForwardRequestWithRetry forwards a request to a peer with retry
func (c *GRPCClient) ForwardRequestWithRetry(ctx context.Context, peerAddr string, peerPort int32, domain, bindAddr string, bindPort uint32, forwardID, originalAddr string) (*pb.ForwardResponseMessage, error) {
	var lastErr error
	maxRetries := 3
	
	for retry := 0; retry < maxRetries; retry++ {
		// Add backoff delay for retries
		if retry > 0 {
			backoffTime := time.Duration(retry) * 500 * time.Millisecond
			logrus.Infof("Retry %d/%d forwarding request to %s:%d after %v", 
				retry+1, maxRetries, peerAddr, peerPort, backoffTime)
			time.Sleep(backoffTime)
		}
		
		resp, err := c.ForwardRequest(ctx, peerAddr, peerPort, domain, bindAddr, bindPort, forwardID, originalAddr)
		if err == nil {
			return resp, nil
		}
		
		lastErr = err
		logrus.Warnf("Failed to forward request to %s:%d (attempt %d/%d): %v", 
			peerAddr, peerPort, retry+1, maxRetries, err)
	}
	
	return nil, fmt.Errorf("failed to forward request after %d attempts: %w", maxRetries, lastErr)
}