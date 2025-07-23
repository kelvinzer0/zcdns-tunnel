package server

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/auth"
	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/proxy"
	channelHandlers "zcdns-tunnel/internal/ssh/channel"
	"zcdns-tunnel/internal/tunnel"
)

// forwarder represents an active TCP forward.
type forwarder struct {
	// For shared forwards, this is the address of the intermediary TCP proxy.
	// For dedicated forwards, this is the public listen address.
	internalListenAddr string
	cancel             context.CancelFunc
}

func (s *SSHServer) handleChannel(sshConn *gossh.ServerConn, newChannel gossh.NewChannel) {
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		channelHandlers.HandleDirectTCPIP(sshConn, newChannel)
	case "forwarded-tcpip":
		channelHandlers.HandleForwardedTCPIP(sshConn, newChannel)
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

	// For shared, public-facing listeners (0.0.0.0)
	sniListeners         map[string]*proxy.SNIProxy
	sniListenerRefCounts map[string]int
	sniListenerCancel    map[string]context.CancelFunc

	// For private, per-connection listeners (127.0.0.1)
	// and for intermediary listeners for shared forwards.
	tcpListeners map[string]context.CancelFunc

	mu sync.Mutex
}

// NewSSHServer creates a new SSH server instance.
func NewSSHServer(cfg config.ServerConfig) *SSHServer {
	return &SSHServer{
		Config:               cfg,
		Manager:              tunnel.NewManager(),
		sniListeners:         make(map[string]*proxy.SNIProxy),
		sniListenerRefCounts: make(map[string]int),
		sniListenerCancel:    make(map[string]context.CancelFunc),
		tcpListeners:         make(map[string]context.CancelFunc),
	}
}

// StartSSHServer starts the SSH listener.
func (s *SSHServer) StartSSHServer(ctx context.Context) error {
	logrus.Printf("Starting SSH server on %s", s.Config.SshListenAddr)

	hostSigner, err := auth.LoadHostKey(s.Config.SshHostKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load SSH host key: %w", err)
	}

	sshConfig := &gossh.ServerConfig{
		PublicKeyCallback: auth.NewSSHAuthenticator(s.Config.ValidationDomain).PublicKeyCallback(),
		Config:            gossh.Config{},
	}
	sshConfig.AddHostKey(hostSigner)

	listener := NewSSHListener(s.Config.SshListenAddr, sshConfig)
	return listener.ListenAndServe(ctx, s.handleSSHConnection)
}

func (s *SSHServer) handleSSHConnection(conn net.Conn, sshConfig *gossh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := gossh.NewServerConn(conn, sshConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   conn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to handshake SSH")
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
		// Shutdown the dedicated/intermediary listener
		fwd.cancel()
		delete(s.tcpListeners, fwd.internalListenAddr)

		// If it was a shared listener, update the SNI proxy
		if sniProxy, exists := s.sniListeners[publicAddr]; exists {
			sniProxy.ClearDefaultTCPBackend(fwd.internalListenAddr)
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

func (s *SSHServer) handleGlobalRequests(ctx context.Context, sshConn *gossh.ServerConn, reqs <-chan *gossh.Request, activeForwards map[string]*forwarder) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		return
	}

	for req := range reqs {
		go func(req *gossh.Request) {
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

func (s *SSHServer) handleTCPIPForward(ctx context.Context, sshConn *gossh.ServerConn, req *gossh.Request, activeForwards map[string]*forwarder, domain string) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}

	publicListenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))
	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"listen_addr": publicListenAddr,
		"domain":      domain,
	}).Info("Received tcpip-forward request")

	s.mu.Lock()
	defer s.mu.Unlock()

	// --- SHARED LISTENER (0.0.0.0) LOGIC ---
	if payload.BindAddr == "0.0.0.0" {
		// 1. Ensure the public SNIProxy listener exists
		sniProxy, exists := s.sniListeners[publicListenAddr]
		if !exists {
			sniProxy = proxy.NewSNIProxy(s.Manager, publicListenAddr)
			s.sniListeners[publicListenAddr] = sniProxy

			sniCtx, sniCancel := context.WithCancel(context.Background())
			s.sniListenerCancel[publicListenAddr] = sniCancel

			go func() {
				if err := sniProxy.ListenAndServe(sniCtx); err != nil {
					logrus.WithError(err).WithField("listen_addr", publicListenAddr).Error("SNI proxy exited with error")
				}
			}()
		}

		// 2. Create the intermediary TCP proxy on 127.0.0.1:0
		intermediaryAddr := "127.0.0.1:0"
		intermediaryProxy := proxy.NewTCPProxy(intermediaryAddr, sshConn)
		intermedCtx, intermedCancel := context.WithCancel(ctx)

		go func() {
			if err := intermediaryProxy.ListenAndServe(intermedCtx); err != nil {
				logrus.WithError(err).WithField("listen_addr", intermediaryAddr).Warn("Intermediary TCP proxy exited with error")
			}
		}()

		// 3. Get the actual listening port of the intermediary
		intermedPort, err := intermediaryProxy.GetListenPort(5 * time.Second)
		if err != nil {
			logrus.WithError(err).Error("Failed to get intermediary listener port")
			intermedCancel()
			req.Reply(false, nil)
			return
		}
		actualIntermediaryAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(intermedPort)))

		// 4. Set the intermediary as the default backend for the SNI proxy
		if !sniProxy.SetDefaultTCPBackend(actualIntermediaryAddr) {
			logrus.WithField("listen_addr", publicListenAddr).Warn("Could not set default TCP backend, one already exists.")
			// We don't treat this as a fatal error. The client can still serve SNI/HTTP.
		}

		// 5. Record the forward
		s.tcpListeners[actualIntermediaryAddr] = intermedCancel
		activeForwards[publicListenAddr] = &forwarder{
			internalListenAddr: actualIntermediaryAddr,
			cancel:             intermedCancel,
		}
		s.sniListenerRefCounts[publicListenAddr]++

		// 6. Reply to client with the public port
		publicPort, err := sniProxy.GetListenPort(5 * time.Second)
		if err != nil {
			logrus.WithError(err).Error("Failed to get public SNI listener port")
			req.Reply(false, nil)
			return
		}
		s.Manager.StoreUserBindingPort(domain, publicPort)
		req.Reply(true, gossh.Marshal(struct{ Port uint32 }{Port: publicPort}))
		logrus.WithFields(logrus.Fields{"public_port": publicPort, "intermediary_addr": actualIntermediaryAddr}).Info("Shared forward established")

		return
	}

	// --- DEDICATED LISTENER (e.g., 127.0.0.1) LOGIC ---
	if _, exists := s.tcpListeners[publicListenAddr]; exists {
		logrus.WithField("listen_addr", publicListenAddr).Warn("Dedicated listener address already in use")
		req.Reply(false, nil)
		return
	}

	tcpProxy := proxy.NewTCPProxy(publicListenAddr, sshConn)
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
		internalListenAddr: actualListenAddr, // For dedicated, internal is the same as public
		cancel:             cancel,
	}

	s.Manager.StoreUserBindingPort(domain, actualPort)
	req.Reply(true, gossh.Marshal(struct{ Port uint32 }{Port: actualPort}))
	logrus.WithField("actual_port", actualPort).Info("Dedicated forward established")
}

func (s *SSHServer) handleCancelTCPIPForward(req *gossh.Request, activeForwards map[string]*forwarder) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}
	publicListenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))

	s.mu.Lock()
	defer s.mu.Unlock()

	if fwd, exists := activeForwards[publicListenAddr]; exists {
		// Stop the listener (intermediary or dedicated)
		fwd.cancel()
		delete(s.tcpListeners, fwd.internalListenAddr)

		// If it was a shared listener, update the SNI proxy
		if sniProxy, ok := s.sniListeners[publicListenAddr]; ok {
			sniProxy.ClearDefaultTCPBackend(fwd.internalListenAddr)
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
