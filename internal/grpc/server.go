package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"zcdns-tunnel/internal/config"
	pb "zcdns-tunnel/internal/grpc/proto"
)

// PeerInfo stores information about a peer node
type PeerInfo struct {
	Address       string
	GossipPort    int32
	SSHPort       int32
	SSHListenAddr string
	LastSeen      time.Time
	Active        bool
}

// GRPCServer implements the gRPC server for node communication
type GRPCServer struct {
	pb.UnimplementedGossipServiceServer
	config         config.GossipConfig
	localAddr      string
	server         *grpc.Server
	peers          map[string]*PeerInfo
	peersMu        sync.RWMutex
	peerUpdateCh   chan struct{}
	stopCh         chan struct{}
	wg             sync.WaitGroup
	forwardHandler ForwardHandler
}

// NewGRPCServer creates a new gRPC server instance
func NewGRPCServer(cfg config.GossipConfig, localAddr string) *GRPCServer {
	return &GRPCServer{
		config:         cfg,
		localAddr:      localAddr,
		peers:          make(map[string]*PeerInfo),
		peerUpdateCh:   make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		forwardHandler: &defaultForwardHandler{},
	}
}

// Start starts the gRPC server
func (s *GRPCServer) Start(ctx context.Context) error {
	// Create a listener on the configured port
	addr := fmt.Sprintf(":%d", s.config.GrpcPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Configure server options
	var opts []grpc.ServerOption
	
	// Add TLS if configured
	if s.config.UseTLS {
		if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
			return fmt.Errorf("TLS is enabled but cert or key file is not specified")
		}
		
		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert/key: %w", err)
		}
		
		creds := credentials.NewServerTLSFromCert(&cert)
		opts = append(opts, grpc.Creds(creds))
	}
	
	// Add keepalive parameters
	kaParams := keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAge:      30 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               1 * time.Second,
	}
	opts = append(opts, grpc.KeepaliveParams(kaParams))
	
	// Create the server
	s.server = grpc.NewServer(opts...)
	pb.RegisterGossipServiceServer(s.server, s)
	
	// Add self to peers
	s.peersMu.Lock()
	s.peers[s.localAddr] = &PeerInfo{
		Address:    s.localAddr,
		GossipPort: int32(s.config.GrpcPort),
		LastSeen:   time.Now(),
		Active:     true,
	}
	s.peersMu.Unlock()
	
	// Start background tasks
	s.wg.Add(2)
	go s.checkPeerStatus(ctx)
	go s.discoverAndJoin(ctx)
	
	// Start the server
	logrus.Infof("gRPC server listening on %s", addr)
	go func() {
		if err := s.server.Serve(lis); err != nil {
			logrus.Errorf("gRPC server failed: %v", err)
		}
	}()
	
	return nil
}

// Stop stops the gRPC server
func (s *GRPCServer) Stop() {
	logrus.Info("Stopping gRPC server...")
	close(s.stopCh)
	
	if s.server != nil {
		s.server.GracefulStop()
	}
	
	s.wg.Wait()
	logrus.Info("gRPC server stopped")
}

// Join handles a join request from another node
func (s *GRPCServer) Join(ctx context.Context, req *pb.JoinRequest) (*pb.JoinResponse, error) {
	if req.NewNode == nil {
		return &pb.JoinResponse{
			Success: false,
			Error:   "New node information is missing",
		}, nil
	}
	
	nodeAddr := req.NewNode.Address
	logrus.Infof("Received JOIN request from %s", nodeAddr)
	
	// Update peer information
	s.updatePeer(req.NewNode)
	
	// Get known peers to send back
	var knownPeers []*pb.Node
	s.peersMu.RLock()
	for addr, peer := range s.peers {
		if addr != nodeAddr && addr != s.localAddr && peer.Active {
			knownPeers = append(knownPeers, &pb.Node{
				Address:       peer.Address,
				GossipPort:    peer.GossipPort,
				SshPort:       peer.SSHPort,
				SshListenAddr: peer.SSHListenAddr,
			})
		}
	}
	s.peersMu.RUnlock()
	
	return &pb.JoinResponse{
		Success:    true,
		KnownPeers: knownPeers,
	}, nil
}

// Heartbeat handles a heartbeat request from another node
func (s *GRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.Sender == nil {
		return &pb.HeartbeatResponse{
			Success: false,
			Error:   "Sender information is missing",
		}, nil
	}
	
	// Update sender information
	s.updatePeer(req.Sender)
	
	// Update known peers
	for _, peer := range req.KnownPeers {
		if peer.Address != s.localAddr {
			s.updatePeer(peer)
		}
	}
	
	// Get known peers to send back
	var knownPeers []*pb.Node
	s.peersMu.RLock()
	for addr, peer := range s.peers {
		if addr != req.Sender.Address && addr != s.localAddr && peer.Active {
			knownPeers = append(knownPeers, &pb.Node{
				Address:       peer.Address,
				GossipPort:    peer.GossipPort,
				SshPort:       peer.SSHPort,
				SshListenAddr: peer.SSHListenAddr,
			})
		}
	}
	s.peersMu.RUnlock()
	
	return &pb.HeartbeatResponse{
		Success:    true,
		KnownPeers: knownPeers,
	}, nil
}

// ForwardRequest handles a forward request from another node
func (s *GRPCServer) ForwardRequest(ctx context.Context, req *pb.ForwardRequestMessage) (*pb.ForwardResponseMessage, error) {
	logrus.WithFields(logrus.Fields{
		"domain":        req.Domain,
		"bind_addr":     req.BindAddr,
		"bind_port":     req.BindPort,
		"forward_id":    req.ForwardId,
		"original_addr": req.OriginalAddr,
		"sender":        req.Sender.Address,
	}).Info("Received forward request")
	
	// Update the sender peer information
	if req.Sender != nil {
		s.updatePeer(req.Sender)
	}
	
	// Use the forward handler to process the request
	return s.forwardHandler.HandleForwardRequest(ctx, req)
}

// updatePeer updates the peer information
func (s *GRPCServer) updatePeer(node *pb.Node) {
	if node.Address == "" || node.Address == s.localAddr {
		return
	}
	
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	
	isNew := false
	if _, exists := s.peers[node.Address]; !exists {
		isNew = true
	}
	
	s.peers[node.Address] = &PeerInfo{
		Address:       node.Address,
		GossipPort:    node.GossipPort,
		SSHPort:       node.SshPort,
		SSHListenAddr: node.SshListenAddr,
		LastSeen:      time.Now(),
		Active:        true,
	}
	
	if isNew {
		logrus.Infof("Discovered new peer: %s", node.Address)
		select {
		case s.peerUpdateCh <- struct{}{}:
		default:
		}
	}
}

// checkPeerStatus periodically checks peer status
func (s *GRPCServer) checkPeerStatus(ctx context.Context) {
	defer s.wg.Done()
	
	probeInterval, err := time.ParseDuration(s.config.ProbeInterval)
	if err != nil {
		probeInterval = 1 * time.Second
	}
	
	probeTimeout, err := time.ParseDuration(s.config.ProbeTimeout)
	if err != nil {
		probeTimeout = 3 * time.Second
	}
	
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			var deadPeers []string
			
			s.peersMu.Lock()
			for addr, peer := range s.peers {
				if addr == s.localAddr {
					continue
				}
				
				if time.Since(peer.LastSeen) > probeTimeout {
					if peer.Active {
						logrus.Warnf("Peer %s detected as dead (last seen %s ago)", 
							addr, time.Since(peer.LastSeen).Round(time.Second))
						peer.Active = false
						deadPeers = append(deadPeers, addr)
					}
				}
			}
			s.peersMu.Unlock()
			
			if len(deadPeers) > 0 {
				select {
				case s.peerUpdateCh <- struct{}{}:
				default:
				}
			}
			
			// Send heartbeats to active peers
			s.sendHeartbeats(ctx)
		}
	}
}

// sendHeartbeats sends heartbeats to active peers
func (s *GRPCServer) sendHeartbeats(ctx context.Context) {
	s.peersMu.RLock()
	peers := make(map[string]*PeerInfo)
	for addr, peer := range s.peers {
		if addr != s.localAddr && peer.Active {
			peers[addr] = peer
		}
	}
	s.peersMu.RUnlock()
	
	if len(peers) == 0 {
		return
	}
	
	// Create the sender node info
	sender := &pb.Node{
		Address:    s.localAddr,
		GossipPort: int32(s.config.GrpcPort),
	}
	
	// Create known peers list
	var knownPeers []*pb.Node
	s.peersMu.RLock()
	for addr, peer := range s.peers {
		if addr != s.localAddr && peer.Active {
			knownPeers = append(knownPeers, &pb.Node{
				Address:       peer.Address,
				GossipPort:    peer.GossipPort,
				SshPort:       peer.SSHPort,
				SshListenAddr: peer.SSHListenAddr,
			})
		}
	}
	s.peersMu.RUnlock()
	
	// Create the heartbeat request
	req := &pb.HeartbeatRequest{
		Sender:     sender,
		KnownPeers: knownPeers,
	}
	
	// Send heartbeats to all active peers
	for addr, peer := range peers {
		go func(addr string, peer *PeerInfo) {
			conn, err := s.dialPeer(addr, peer.GossipPort)
			if err != nil {
				logrus.Warnf("Failed to dial peer %s: %v", addr, err)
				return
			}
			defer conn.Close()
			
			client := pb.NewGossipServiceClient(conn)
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			
			_, err = client.Heartbeat(ctxWithTimeout, req)
			if err != nil {
				logrus.Warnf("Failed to send heartbeat to %s: %v", addr, err)
			}
		}(addr, peer)
	}
}

// dialPeer creates a gRPC connection to a peer
func (s *GRPCServer) dialPeer(addr string, port int32) (*grpc.ClientConn, error) {
	target := fmt.Sprintf("%s:%d", addr, port)
	
	// Configure dial options
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTimeout(2 * time.Second),
	}
	
	// Add TLS if configured
	if s.config.UseTLS {
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

// discoverAndJoin discovers and joins the cluster
func (s *GRPCServer) discoverAndJoin(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	// Attempt to join immediately
	s.attemptJoin(ctx)
	
	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.attemptJoin(ctx)
		}
	}
}

// attemptJoin attempts to join the cluster
func (s *GRPCServer) attemptJoin(ctx context.Context) {
	// If we already have peers, we might already be connected
	s.peersMu.RLock()
	peerCount := 0
	for addr, peer := range s.peers {
		if addr != s.localAddr && peer.Active {
			peerCount++
		}
	}
	s.peersMu.RUnlock()
	
	if peerCount > 0 {
		return
	}
	
	// TODO: Implement peer discovery from validation domain
	// For now, this is a placeholder
	logrus.Info("No peers found, waiting for other nodes to join")
}

// GetActivePeerAddrs returns the addresses of active peers
func (s *GRPCServer) GetActivePeerAddrs() []string {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	
	var active []string
	for addr, peer := range s.peers {
		if peer.Active {
			active = append(active, addr)
		}
	}
	
	return active
}

// GetPeerUpdateChan returns the peer update channel
func (s *GRPCServer) GetPeerUpdateChan() <-chan struct{} {
	return s.peerUpdateCh
}
// GetLocalAddr returns the local address of the node
func (s *GRPCServer) GetLocalAddr() string {
	return s.localAddr
}
// ShareIntermediaryAddr handles a share intermediary address request from another node
func (s *GRPCServer) ShareIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrMessage) (*pb.IntermediaryAddrResponse, error) {
	logrus.WithFields(logrus.Fields{
		"domain":           req.Domain,
		"protocol_prefix":  req.ProtocolPrefix,
		"public_port":      req.PublicPort,
		"intermediary_addr": req.IntermediaryAddr,
		"forward_id":       req.ForwardId,
		"sender":           req.Sender.Address,
	}).Info("Received share intermediary address request")
	
	// Update the sender peer information
	if req.Sender != nil {
		s.updatePeer(req.Sender)
	}
	
	// Store the intermediary address in the shared state
	handler, ok := s.IntermediaryAddrHandlerInstance()
	if !ok {
		return &pb.IntermediaryAddrResponse{
			Success: false,
			Error:   "No handler available for intermediary address sharing",
		}, nil
	}
	
	success, err := handler.HandleShareIntermediaryAddr(ctx, req)
	if err != nil {
		return &pb.IntermediaryAddrResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}
	
	return &pb.IntermediaryAddrResponse{
		Success: success,
	}, nil
}

// GetIntermediaryAddr handles a get intermediary address request from another node
func (s *GRPCServer) GetIntermediaryAddr(ctx context.Context, req *pb.IntermediaryAddrRequest) (*pb.IntermediaryAddrMessage, error) {
	logrus.WithFields(logrus.Fields{
		"domain":          req.Domain,
		"protocol_prefix": req.ProtocolPrefix,
		"public_port":     req.PublicPort,
		"forward_id":      req.ForwardId,
		"sender":          req.Sender.Address,
	}).Info("Received get intermediary address request")
	
	// Update the sender peer information
	if req.Sender != nil {
		s.updatePeer(req.Sender)
	}
	
	// Get the intermediary address from the shared state
	handler, ok := s.IntermediaryAddrHandlerInstance()
	if !ok {
		return &pb.IntermediaryAddrMessage{
			Domain:          req.Domain,
			ProtocolPrefix:  req.ProtocolPrefix,
			PublicPort:      req.PublicPort,
			IntermediaryAddr: "",
			ForwardId:       req.ForwardId,
			Sender:          req.Sender,
		}, nil
	}
	
	return handler.HandleGetIntermediaryAddr(ctx, req)
}