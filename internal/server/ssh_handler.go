package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/auth"
	"zcdns-tunnel/internal/common"
	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/consistenthash"
	"zcdns-tunnel/internal/gossip"
	"zcdns-tunnel/internal/grpc"
	"zcdns-tunnel/internal/proxy"
	channelHandlers "zcdns-tunnel/internal/ssh/channel"
	"zcdns-tunnel/internal/tunnel"
	"zcdns-tunnel/internal/udpproto"
)

// forwarder represents an active TCP forward.
type forwarder struct {
	// For shared forwards that are the default handler, this is the
	// address of the intermediary TCP proxy. For others, it's empty.
	// For dedicated forwards, this is the public listen address.
	internalListenAddr string
	cancel             context.CancelFunc
}

func (s *SSHServer) handleChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		channelHandlers.HandleDirectTCPIP(sshConn, newChannel)
	case "forwarded-tcpip":
		channelHandlers.HandleForwardedTCPIP(sshConn, newChannel, s.forwardedClientConns, &s.mu)
	case "session":
		channelHandlers.HandleSession(sshConn, newChannel)
	default:
		channelHandlers.HandleUnsupportedChannel(sshConn, newChannel)
	}
}

// SSHServer represents the SSH server for managing tunnels.
type SSHServer struct {
	Config  config.ServerConfig
	Manager *tunnel.Manager

	// For distributed system components
	GossipService   common.GossipProvider
	UDPService      *udpproto.UDPService
	ConsistentHash  *consistenthash.Map
	LocalGossipAddr string // The local address of this node for consistent hashing
	GRPCClient      *grpc.GRPCClient // gRPC client for communication with other nodes

	interNodeSSHClientConfig *ssh.ClientConfig // SSH client config for inter-node communication
	interNodeSigner          ssh.Signer        // SSH signer for inter-node communication

	// For shared, public-facing listeners (0.0.0.0)
	sniListeners         map[string]*proxy.SNIProxy
	sniListenerRefCounts map[string]int
	sniListenerCancel    map[string]context.CancelFunc

	// For private, per-connection listeners (127.0.0.1)
	// and for intermediary listeners for shared forwards.
	tcpListeners map[string]context.CancelFunc

	// Map to store original client SSH connections for forwarded requests
	forwardedClientConns map[string]*ssh.ServerConn

	mu sync.Mutex
}

// NewSSHServer creates a new SSH server instance.
func NewSSHServer(cfg config.ServerConfig, gs common.GossipProvider, localGossipAddr string) (*SSHServer, error) {
	// Load inter-node SSH client key
	interNodeSigner, err := auth.LoadHostKey(cfg.InterNodeSSHKeyPath)
	if err != nil {
		logrus.Fatalf("Failed to load inter-node SSH key: %v", err)
	}

	interNodeSSHClientConfig := &ssh.ClientConfig{
		User: "inter-node", // A fixed username for inter-node communication
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(interNodeSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // WARNING: Insecure for production. Consider known_hosts or custom validation.
		Timeout:         5 * time.Second,
	}

	// Check if the gossip provider also implements UDPProvider
	var udpService *udpproto.UDPService
	if udpProvider, ok := gs.(common.UDPProvider); ok {
		// Tidak menggunakan cluster secret untuk meningkatkan performa
		logrus.Info("Initializing UDP service without cluster secret for better performance")
		
		// Initialize UDP service using the UDP connection from the gossip service
		udpService = udpproto.UDPServiceFromGossip(udpProvider)
		
		// Check if the UDP connection was successfully shared
		if udpService.GetUDPConn() == nil {
			logrus.Warn("Failed to get UDP connection from gossip service, UDP-based communication will be disabled")
		} else {
			logrus.Infof("Successfully initialized UDP service with shared connection from gossip service")
		}
	} else {
		// If the gossip provider doesn't implement UDPProvider, create a dummy UDP service
		// This is fine for gRPC-based communication as we won't be using UDP
		logrus.Info("Gossip provider doesn't support UDP, UDP-based communication will be disabled")
		udpService = &udpproto.UDPService{}
	}

	// Create a gRPC client for communication with other nodes
	grpcClient := grpc.NewGRPCClient(cfg.Gossip, localGossipAddr)
	logrus.Info("Initialized gRPC client for inter-node communication")

	server := &SSHServer{
		Config:                   cfg,
		Manager:                  tunnel.NewManager(),
		GossipService:            gs,
		UDPService:               udpService,
		ConsistentHash:           consistenthash.New(100, nil), // 100 virtual nodes per real node
		LocalGossipAddr:          localGossipAddr,
		GRPCClient:               grpcClient,
		interNodeSSHClientConfig: interNodeSSHClientConfig,
		interNodeSigner:          interNodeSigner,
		sniListeners:             make(map[string]*proxy.SNIProxy),
		sniListenerRefCounts:     make(map[string]int),
		sniListenerCancel:        make(map[string]context.CancelFunc),
		tcpListeners:             make(map[string]context.CancelFunc),
		forwardedClientConns:     make(map[string]*ssh.ServerConn),
	}

	// Register UDP message handlers if UDP service is available
	if udpService.GetUDPConn() != nil {
		udpService.RegisterHandler(udpproto.MessageTypeForward, server.handleForwardRequest)
		udpService.RegisterHandler(udpproto.MessageTypeForwardResponse, server.handleForwardResponse)
	}

	// If the gossip provider is a GRPCServer, register the server as the forward handler
	if grpcServer, ok := gs.(*grpc.GRPCServer); ok {
		handler := newSSHForwardHandler(server)
		grpcServer.SetForwardHandler(handler)
		logrus.Info("Registered SSH server as gRPC forward handler")
	}

	return server, nil
}

// StartSSHServer starts the SSH listener.
func (s *SSHServer) StartSSHServer(ctx context.Context) error {
	logrus.Printf("Starting SSH server on %s", s.Config.SshListenAddr)

	hostSigner, err := auth.LoadHostKey(s.Config.SshHostKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load SSH host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: auth.NewSSHAuthenticator(s.Config.ValidationDomain).PublicKeyCallback(),
		Config:            ssh.Config{},
	}
	sshConfig.AddHostKey(hostSigner)

	// Start UDP service for inter-node communication if available
	if s.UDPService != nil && s.UDPService.GetUDPConn() != nil {
		if err := s.UDPService.StartWithExistingConn(ctx); err != nil {
			logrus.Warnf("Failed to start UDP service: %v", err)
			logrus.Info("Continuing without UDP service, will use gRPC if available")
		} else {
			logrus.Info("UDP service started successfully")
		}
	} else {
		logrus.Info("UDP service not available, will use gRPC for communication")
	}

	go func() {
		for range s.GossipService.GetPeerUpdateChan() {
			logrus.Debug("Peer list updated, rebuilding consistent hash ring.")
			s.mu.Lock()
			// Clear existing nodes
			s.ConsistentHash = consistenthash.New(100, nil) // Re-initialize to clear
			// Add active peers
			activePeers := s.GossipService.GetActivePeerAddrs()
			if len(activePeers) > 0 {
				s.ConsistentHash.Add(activePeers...)
				logrus.Debugf("Consistent hash ring rebuilt with %d active peers.", len(activePeers))
			} else {
				logrus.Warn("Consistent hash ring is empty, no active peers.")
			}
			s.mu.Unlock()
		}
	}()

	// Initial build of the consistent hash ring
	s.mu.Lock()
	activePeers := s.GossipService.GetActivePeerAddrs()
	if len(activePeers) > 0 {
		s.ConsistentHash.Add(activePeers...)
		logrus.Debugf("Initial consistent hash ring built with %d active peers.", len(activePeers))
	} else {
		logrus.Warn("Initial consistent hash ring is empty, no active peers.")
	}
	s.mu.Unlock()

	listener := NewSSHListener(s.Config.SshListenAddr, sshConfig)
	go func() {
		if err := listener.ListenAndServe(ctx, s.handleSSHConnection); err != nil {
			logrus.WithError(err).Error("Main SSH listener exited with error")
		}
	}()

	// Start inter-node SSH listener on gossip port
	interNodeSSHConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Only allow the inter-node SSH key for authentication
			if bytes.Equal(key.Marshal(), s.interNodeSigner.PublicKey().Marshal()) {
				logrus.WithFields(logrus.Fields{
					"remote_addr": conn.RemoteAddr(),
					"user":        conn.User(),
				}).Info("Inter-node SSH authentication successful")
				return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
			}
			logrus.WithFields(logrus.Fields{
				"remote_addr": conn.RemoteAddr(),
				"user":        conn.User(),
				"fingerprint": ssh.FingerprintSHA256(key),
			}).Warn("Inter-node SSH authentication failed: unauthorized key")
			return nil, fmt.Errorf("unknown public key for inter-node communication")
		},
		Config: ssh.Config{},
	}
	// Add the host key for the inter-node listener (same as main listener)
	interNodeSSHConfig.AddHostKey(hostSigner)

	interNodeListener := NewSSHListener(fmt.Sprintf(":%d", gossip.DefaultGossipPort), interNodeSSHConfig)
	go func() {
		logrus.Infof("Starting inter-node SSH listener on :%d", gossip.DefaultGossipPort)
		if err := interNodeListener.ListenAndServe(ctx, s.handleSSHConnection); err != nil {
			logrus.WithError(err).Error("Inter-node SSH listener exited with error")
		}
	}()

	// Wait for context to be cancelled to gracefully shut down both listeners
	<-ctx.Done()
	logrus.Info("SSH servers shutting down.")
	
	// Stop UDP service if it's running
	if s.UDPService != nil && s.UDPService.GetUDPConn() != nil {
		s.UDPService.Stop()
	}
	
	return nil
}

func (s *SSHServer) handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	// For TCP connections, set TCP keepalive to detect and recover from network issues
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Set TCP keepalive to detect dead connections
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		
		// Set a longer timeout for the SSH handshake
		tcpConn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	// Try to establish SSH connection with better error handling
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	
	// Reset the deadline after handshake
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetDeadline(time.Time{})
	}
	
	if err != nil {
		// Provide more detailed logging for SSH handshake failures
		logFields := logrus.Fields{
			"remote_addr":   conn.RemoteAddr(),
			logrus.ErrorKey: err,
		}
		
		// Add connection details for debugging
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			localAddr := tcpConn.LocalAddr()
			if localAddr != nil {
				logFields["local_addr"] = localAddr.String()
			}
		}
		
		// Check for specific error types
		if err == io.EOF {
			logFields["error_type"] = "EOF"
			logrus.WithFields(logFields).Error("SSH handshake failed with EOF - client disconnected prematurely")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logFields["error_type"] = "Timeout"
			logrus.WithFields(logFields).Error("SSH handshake failed with timeout - consider increasing handshake timeout")
		} else if strings.Contains(err.Error(), "connection reset by peer") {
			logFields["error_type"] = "ConnectionReset"
			logrus.WithFields(logFields).Error("SSH handshake failed - connection reset by peer")
		} else if strings.Contains(err.Error(), "protocol negotiation failed") {
			logFields["error_type"] = "ProtocolNegotiationFailed"
			logrus.WithFields(logFields).Error("SSH protocol negotiation failed - check client compatibility")
		} else {
			logFields["error_type"] = "Other"
			logrus.WithFields(logFields).Error("Failed to handshake SSH")
		}
		return
	}
	logrus.WithFields(logrus.Fields{
		"remote_addr":    sshConn.RemoteAddr(),
		"client_version": string(sshConn.ClientVersion()),
	}).Info("New SSH connection")

	domain, ok := sshConn.Permissions.Extensions["domain"]
	if ok && domain != "" {
		s.Manager.StoreClient(domain, sshConn)
	}

	// activeForwards maps the *public* listen address to its forwarder details.
	activeForwards := make(map[string]*forwarder)

	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	go s.handleGlobalRequests(connCtx, sshConn, reqs, activeForwards)

	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel)
	}

	<-connCtx.Done() // Wait for connection to be explicitly closed.

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Info("SSH connection closed. Cleaning up resources.")

	if ok && domain != "" {
		s.Manager.DeleteClient(domain, sshConn)
		s.Manager.DeleteDomainForwardedPort(domain)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for publicAddr, fwd := range activeForwards {
		// If this forwarder had an intermediary/dedicated listener, shut it down.
		if fwd.internalListenAddr != "" {
			fwd.cancel()
			delete(s.tcpListeners, fwd.internalListenAddr)
		}

		// If it was a shared listener, decrement its reference count.
		if _, exists := s.sniListeners[publicAddr]; exists {
			s.sniListenerRefCounts[publicAddr]--
			if s.sniListenerRefCounts[publicAddr] <= 0 {
				logrus.WithFields(logrus.Fields{
					"listen_addr": publicAddr,
				}).Info("Shutting down dynamic SNI listener as no more references")
				s.sniListenerCancel[publicAddr]()
				delete(s.sniListeners, publicAddr)
				delete(s.sniListenerRefCounts, publicAddr)
				delete(s.sniListenerCancel, publicAddr)
			}
		}
	}
}

func (s *SSHServer) handleGlobalRequests(ctx context.Context, sshConn *ssh.ServerConn, reqs <-chan *ssh.Request, activeForwards map[string]*forwarder) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		return
	}

	for req := range reqs {
		go func(req *ssh.Request) {
			switch req.Type {
			case "tcpip-forward":
				s.handleTCPIPForward(ctx, sshConn, req, activeForwards, domain)
			case "cancel-tcpip-forward":
				s.handleCancelTCPIPForward(req, activeForwards)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}(req)
	}
}

func (s *SSHServer) handleTCPIPForward(ctx context.Context, sshConn *ssh.ServerConn, req *ssh.Request, activeForwards map[string]*forwarder, domain string) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}

	publicListenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))
	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"listen_addr": publicListenAddr,
		"domain":      domain,
	}).Info("Received tcpip-forward request")

	// Determine which node is responsible for this domain using Consistent Hashing
	responsibleNode := s.ConsistentHash.Get(domain)

	if responsibleNode == "" {
		logrus.WithFields(logrus.Fields{
			"domain": domain,
		}).Error("No responsible node found for domain in consistent hash ring. Make sure the gossip protocol is working correctly and at least one node is active.")
		req.Reply(false, nil)
		return
	}

	if responsibleNode != s.LocalGossipAddr {
		logrus.WithFields(logrus.Fields{
			"domain":           domain,
			"responsible_node": responsibleNode,
			"current_node":     s.LocalGossipAddr,
		}).Info("Domain is not handled by this node, forwarding request to responsible node.")

		// Generate a unique ID for this forwarded request
		forwardID := fmt.Sprintf("%s-%s-%d", sshConn.RemoteAddr().String(), payload.BindAddr, payload.BindPort)

		// Store the original client's SSH connection for later use when the forwarded channel comes back
		s.mu.Lock()
		s.forwardedClientConns[forwardID] = sshConn
		s.mu.Unlock()

		// Forward the request using the appropriate method (gRPC or UDP)
		ok, port, err := s.forwardToResponsibleNode(ctx, domain, responsibleNode, forwardID, payload.BindAddr, payload.BindPort, sshConn.RemoteAddr().String())
		if err != nil {
			logrus.WithError(err).Errorf("Failed to forward request to responsible node %s", responsibleNode)
			req.Reply(false, nil)
			// Clean up the stored connection if forwarding failed
			s.mu.Lock()
			delete(s.forwardedClientConns, forwardID)
			s.mu.Unlock()
			return
		}

		// Try to get the intermediary address from the responsible node
		// This is needed for the SSH handshake to work correctly
		protocolPrefix, ok := sshConn.Permissions.Extensions["protocol_prefix"]
		if !ok {
			protocolPrefix = ""
		}

		// Attempt to get the intermediary address from the responsible node
		// Use a longer timeout and implement retries
		intermediaryAddrCtx, intermediaryAddrCancel := context.WithTimeout(ctx, 15*time.Second)
		defer intermediaryAddrCancel()
		
		var intermediaryAddr string
		var intermediaryAddrErr error
		
		// Implement retries for getting the intermediary address
		for retries := 0; retries < 5; retries++ {
			if retries > 0 {
				// Add exponential backoff
				backoffTime := time.Duration(1<<uint(retries-1)) * 200 * time.Millisecond
				logrus.Infof("Retrying to get intermediary address from responsible node %s (attempt %d/5, backoff: %v)", 
					responsibleNode, retries+1, backoffTime)
				time.Sleep(backoffTime)
			}
			
			intermediaryAddr, intermediaryAddrErr = s.getIntermediaryAddrFromResponsibleNode(
				intermediaryAddrCtx, domain, responsibleNode, forwardID, protocolPrefix, port)
			
			if intermediaryAddrErr == nil && intermediaryAddr != "" {
				// Successfully got the intermediary address
				break
			}
		}
		
		if intermediaryAddrErr != nil {
			logrus.WithError(intermediaryAddrErr).Warnf("Failed to get intermediary address from responsible node %s after multiple attempts, SSH handshake may fail", responsibleNode)
			// We'll continue without the intermediary address, but SSH handshake may fail
		} else if intermediaryAddr == "" {
			logrus.Warnf("Got empty intermediary address from responsible node %s, SSH handshake may fail", responsibleNode)
			// We'll continue without the intermediary address, but SSH handshake may fail
		} else {
			// Store the intermediary address in our local manager so it can be used when handling forwarded channels
			s.Manager.StoreBridgeAddress(domain, protocolPrefix, port, intermediaryAddr)
			logrus.WithFields(logrus.Fields{
				"domain":           domain,
				"protocol_prefix":  protocolPrefix,
				"port":             port,
				"intermediary_addr": intermediaryAddr,
			}).Info("Stored intermediary address from responsible node")
		}

		// Relay the response back to the original client
		req.Reply(ok, ssh.Marshal(struct{ Port uint32 }{Port: port}))
		return
	}

	// If we reach here, this node is responsible for the domain.

	s.mu.Lock()
	defer s.mu.Unlock()

	// --- SHARED LISTENER (0.0.0.0) LOGIC ---
	if payload.BindAddr == "0.0.0.0" {
		// For shared listeners, we create an intermediary TCP proxy for this specific client
		// to bridge traffic from the main SNI proxy to this client's SSH connection.

		// 1. Create the intermediary TCP proxy on a random port on localhost.
		intermediaryAddr := "127.0.0.1:0"
		// This TCPProxy is special: it listens on the intermediary address, but its job is
		// to forward traffic to the *specific* sshConn that requested it.
		intermediaryProxy := proxy.NewTCPProxy(intermediaryAddr, payload.BindPort, s.LocalGossipAddr, sshConn)
		intermedCtx, intermedCancel := context.WithCancel(ctx)

		go func() {
			if err := intermediaryProxy.ListenAndServe(intermedCtx); err != nil {
				if intermedCtx.Err() == nil {
					logrus.WithError(err).WithField("listen_addr", intermediaryAddr).Warn("Intermediary TCP proxy exited with error")
				}
			}
		}()

		// 2. Get the actual port the intermediary proxy is listening on.
		intermedPort, err := intermediaryProxy.GetListenPort(5 * time.Second)
		if err != nil {
			logrus.WithError(err).Error("Failed to get intermediary listener port")
			intermedCancel()
			req.Reply(false, nil)
			return
		}
		actualIntermediaryAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(intermedPort)))

		// 3. Store the mapping from the client's domain to this new intermediary address.
		protocolPrefix, ok := sshConn.Permissions.Extensions["protocol_prefix"]
		if !ok {
			protocolPrefix = ""
		}

		// 3. Store the mapping from the client's domain, protocol prefix, and public port to this new intermediary address.
		s.Manager.StoreBridgeAddress(domain, protocolPrefix, payload.BindPort, actualIntermediaryAddr)

		// Share the intermediary address with all active peers
		if s.GRPCClient != nil {
			activePeers := s.GossipService.GetActivePeerAddrs()
			for _, peerAddr := range activePeers {
				if peerAddr == s.LocalGossipAddr {
					continue // Skip self
				}
				
				// Extract host from peer address
				host, _, err := net.SplitHostPort(peerAddr)
				if err != nil {
					logrus.Warnf("Failed to parse peer address %s: %v", peerAddr, err)
					host = peerAddr // Use as is if parsing fails
				}
				
				// Get the gRPC port from the configuration
				grpcPort := int32(s.Config.Gossip.GrpcPort)
				
				// Generate a unique ID for this shared address
				shareID := fmt.Sprintf("%s-%s-%d-%s", domain, protocolPrefix, payload.BindPort, sshConn.RemoteAddr().String())
				
				// Share the intermediary address with the peer
				go func(host string, port int32, shareID string) {
					shareCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					
					_, err := s.GRPCClient.ShareIntermediaryAddrWithRetry(
						shareCtx,
						host,
						port,
						domain,
						protocolPrefix,
						payload.BindPort,
						actualIntermediaryAddr,
						shareID,
					)
					
					if err != nil {
						logrus.Warnf("Failed to share intermediary address with peer %s: %v", host, err)
					} else {
						logrus.Infof("Successfully shared intermediary address with peer %s", host)
					}
				}(host, grpcPort, shareID)
			}
		}

		// 4. Ensure the main public SNIProxy listener exists.
		sniProxy, exists := s.sniListeners[publicListenAddr]
		if !exists {
			sniProxy = proxy.NewSNIProxy(s.Manager, publicListenAddr)
			s.sniListeners[publicListenAddr] = sniProxy

			sniCtx, sniCancel := context.WithCancel(context.Background())
			s.sniListenerCancel[publicListenAddr] = sniCancel

			go func() {
				logrus.WithField("listen_addr", publicListenAddr).Info("Starting new dynamic SNI/HTTP listener")
				if err := sniProxy.ListenAndServe(sniCtx); err != nil {
					if sniCtx.Err() == nil {
						logrus.WithError(err).WithField("listen_addr", publicListenAddr).Error("SNI proxy exited with error")
					}
				}
				logrus.WithField("listen_addr", publicListenAddr).Info("SNI/HTTP listener has shut down.")
			}()
		}

		// 5. Register this forward with the connection's active forwards list.
		activeForwards[publicListenAddr] = &forwarder{
			internalListenAddr: actualIntermediaryAddr, // This is the bridge address
			cancel:             intermedCancel,         // This cancels the bridge proxy
		}
		s.tcpListeners[actualIntermediaryAddr] = intermedCancel // Track the listener
		s.sniListenerRefCounts[publicListenAddr]++

		logrus.WithFields(logrus.Fields{
			"domain":        domain,
			"public_listen": publicListenAddr,
			"bridge_addr":   actualIntermediaryAddr,
		}).Info("Client registered for shared port via intermediary bridge")

		// 6. Confirm the forward and return the public port to the client.
		publicPort, err := sniProxy.GetListenPort(5 * time.Second)
		if err != nil {
			logrus.WithError(err).Error("Failed to get public SNI listener port")
			// Cleanup
			s.sniListenerRefCounts[publicListenAddr]--
			intermedCancel()
			delete(s.tcpListeners, actualIntermediaryAddr)
			protocolPrefix, ok := sshConn.Permissions.Extensions["protocol_prefix"]
			if !ok {
				protocolPrefix = ""
			}

			// ... (rest of the function)

			s.Manager.DeleteBridgeAddress(domain, protocolPrefix, payload.BindPort)
			req.Reply(false, nil)
			return
		}

		s.Manager.StoreUserBindingPort(domain, payload.BindPort)
		req.Reply(true, ssh.Marshal(struct{ Port uint32 }{Port: publicPort}))
		logrus.WithFields(logrus.Fields{"public_port": publicPort, "domain": domain}).Info("Shared forward request acknowledged")

		return
	}

	// --- DEDICATED LISTENER (e.g., 127.0.0.1) LOGIC ---
	if _, exists := s.tcpListeners[publicListenAddr]; exists {
		logrus.WithField("listen_addr", publicListenAddr).Warn("Dedicated listener address already in use")
		req.Reply(false, nil)
		return
	}

	tcpProxy := proxy.NewTCPProxy(publicListenAddr, payload.BindPort, s.LocalGossipAddr, sshConn)
	listenerCtx, cancel := context.WithCancel(ctx)

	go func() {
		if err := tcpProxy.ListenAndServe(listenerCtx); err != nil {
			logrus.WithError(err).WithField("listen_addr", publicListenAddr).Warn("Dedicated TCP proxy exited with error")
		}
	}()

	actualPort, err := tcpProxy.GetListenPort(5 * time.Second)
	if err != nil {
		logrus.WithError(err).Error("Failed to get dedicated listener port")
		cancel()
		req.Reply(false, nil)
		return
	}

	actualListenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(actualPort)))
	s.tcpListeners[actualListenAddr] = cancel
	activeForwards[publicListenAddr] = &forwarder{
		internalListenAddr: actualListenAddr,
		cancel:             cancel,
	}

	s.Manager.StoreUserBindingPort(domain, actualPort)
	req.Reply(true, ssh.Marshal(struct{ Port uint32 }{Port: actualPort}))
	logrus.WithField("actual_port", actualPort).Info("Dedicated forward established")
}

func (s *SSHServer) handleCancelTCPIPForward(req *ssh.Request, activeForwards map[string]*forwarder) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}
	publicListenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))

	s.mu.Lock()
	defer s.mu.Unlock()

	if fwd, exists := activeForwards[publicListenAddr]; exists {
		// Stop the listener (intermediary or dedicated)
		if fwd.internalListenAddr != "" {
			fwd.cancel()
			delete(s.tcpListeners, fwd.internalListenAddr)
		}

		// If it was a shared listener, update its reference count.
		if _, ok := s.sniListeners[publicListenAddr]; ok {
			s.sniListenerRefCounts[publicListenAddr]--
			if s.sniListenerRefCounts[publicListenAddr] <= 0 {
				s.sniListenerCancel[publicListenAddr]()
				delete(s.sniListeners, publicListenAddr)
				delete(s.sniListenerRefCounts, publicListenAddr)
				delete(s.sniListenerCancel, publicListenAddr)
			}
		}
		delete(activeForwards, publicListenAddr)
		req.Reply(true, nil)
		logrus.WithField("listen_addr", publicListenAddr).Info("Canceled tcpip-forward")
	} else {
		req.Reply(false, nil)
		logrus.WithField("listen_addr", publicListenAddr).Warn("Received cancel request for unknown forward")
	}
}
