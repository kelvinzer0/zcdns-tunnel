package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/auth"
	"zcdns-tunnel/internal/config"
	proxy_sni "zcdns-tunnel/internal/proxy"
	channelHandlers "zcdns-tunnel/internal/ssh/channel"
	"zcdns-tunnel/internal/tunnel"
)

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

	sniListeners        map[string]*proxy_sni.SNIProxy
	listenerRefCounts   map[string]int
	listenerCancelFuncs map[string]context.CancelFunc
	mu                  sync.Mutex
}

// NewSSHServer creates a new SSH server instance.
func NewSSHServer(cfg config.ServerConfig) *SSHServer {
	return &SSHServer{
		Config:              cfg,
		Manager:             tunnel.NewManager(),
		sniListeners:        make(map[string]*proxy_sni.SNIProxy),
		listenerRefCounts:   make(map[string]int),
		listenerCancelFuncs: make(map[string]context.CancelFunc),
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

	// Track active forwards for this specific SSH connection
	activeForwards := make(map[string]struct{})

	// Store the active client connection by domain
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if ok && domain != "" {
		s.Manager.StoreClient(domain, sshConn)
	}

	// Handle global requests (e.g., tcpip-forward for -R)
	go s.handleGlobalRequests(sshConn, reqs, activeForwards)

	// Service the incoming channels (e.g., direct-tcpip for -L, forwarded-tcpip for -R)
	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel)
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Info("SSH connection closed.")

	// Clean up active client entry and associated remote listeners
	if ok && domain != "" {
		s.Manager.DeleteClient(domain, sshConn)
		s.Manager.DeleteDomainForwardedPort(domain)
	}

	// Clean up dynamically created SNI listeners if no longer referenced
	s.mu.Lock()
	for listenAddr := range activeForwards {
		s.listenerRefCounts[listenAddr]--
		if s.listenerRefCounts[listenAddr] <= 0 {
			logrus.WithFields(logrus.Fields{
				"listen_addr": listenAddr,
			}).Info("Shutting down dynamic SNI listener as no more references")
			if cancel, exists := s.listenerCancelFuncs[listenAddr]; exists {
				cancel()
				delete(s.sniListeners, listenAddr)
				delete(s.listenerRefCounts, listenAddr)
				delete(s.listenerCancelFuncs, listenAddr)
			}
		}
	}
	s.mu.Unlock()
}

func (s *SSHServer) handleGlobalRequests(sshConn *gossh.ServerConn, reqs <-chan *gossh.Request, activeForwards map[string]struct{}) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			listenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"listen_addr": listenAddr,
			}).Info("Received tcpip-forward request")

			s.mu.Lock()
			proxy, exists := s.sniListeners[listenAddr]
			if !exists {
				// Create a new SNI proxy if one doesn't exist for this address
				proxy = proxy_sni.NewSNIProxy(s.Manager, listenAddr)
				s.sniListeners[listenAddr] = proxy
				
				listenerCtx, cancel := context.WithCancel(context.Background())
				s.listenerCancelFuncs[listenAddr] = cancel

				go func() {
					if err := proxy.ListenAndServe(listenerCtx); err != nil {
						logrus.Printf("SNI proxy on %s exited with error: %v", listenAddr, err)
					}
					// Clean up map entries if listener exits prematurely
					s.mu.Lock()
					if s.listenerRefCounts[listenAddr] <= 0 { // Only delete if no active forwards
						delete(s.sniListeners, listenAddr)
						delete(s.listenerRefCounts, listenAddr)
						delete(s.listenerCancelFuncs, listenAddr)
					}
					s.mu.Unlock()
				}()
			}
			s.listenerRefCounts[listenAddr]++
			activeForwards[listenAddr] = struct{}{} // Mark this forward as active for this connection
			s.mu.Unlock()

			// Acknowledge the request
			req.Reply(true, nil)

		case "cancel-tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal cancel-tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			listenAddr := net.JoinHostPort(payload.BindAddr, strconv.Itoa(int(payload.BindPort)))
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"listen_addr": listenAddr,
			}).Info("Received cancel-tcpip-forward request")

			s.mu.Lock()
			if _, exists := activeForwards[listenAddr]; exists {
				s.listenerRefCounts[listenAddr]--
				delete(activeForwards, listenAddr) // Remove from this connection's active forwards
				if s.listenerRefCounts[listenAddr] <= 0 {
					logrus.WithFields(logrus.Fields{
						"listen_addr": listenAddr,
					}).Info("Shutting down dynamic SNI listener as no more references")
					if cancel, exists := s.listenerCancelFuncs[listenAddr]; exists {
						cancel()
						delete(s.sniListeners, listenAddr)
						delete(s.listenerRefCounts, listenAddr)
						delete(s.listenerCancelFuncs, listenAddr)
					}
				}
			} else {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					"listen_addr": listenAddr,
				}).Warn("Received cancel-tcpip-forward for an unknown or inactive forward for this connection")
			}
			s.mu.Unlock()
			req.Reply(true, nil)

		default:
			logrus.WithFields(logrus.Fields{
				"remote_addr":  sshConn.RemoteAddr(),
				"request_type": req.Type,
			}).Warn("Unknown global request type")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleRemoteForwardedConnections accepts connections on a remotely forwarded port
// and proxies them back to the SSH client.
func (s *SSHServer) handleRemoteForwardedConnections(sshConn *gossh.ServerConn, listener net.Listener, bindAddr string, bindPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed, or other error. Log and exit.
			logrus.WithFields(logrus.Fields{
				"remote_addr":   sshConn.RemoteAddr(),
				"bind_addr":     bindAddr,
				"bind_port":     bindPort,
				logrus.ErrorKey: err,
			}).Info("Remote forwarded listener stopped accepting connections.")
			return
		}

		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
			"bind_addr":   bindAddr,
			"bind_port":   bindPort,
			"client_conn": conn.RemoteAddr(),
		}).Info("Accepted connection on remote forwarded port.")

		go func() {
			defer conn.Close()

			// Open a forwarded-tcpip channel back to the client
			channel, requests, err := sshConn.OpenChannel("forwarded-tcpip", gossh.Marshal(&struct {
				ConnectedAddr  string
				ConnectedPort  uint32
				OriginatorIP   string
				OriginatorPort uint32
			}{
				ConnectedAddr:  bindAddr,
				ConnectedPort:  bindPort,
				OriginatorIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
				OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
			}))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					"bind_addr":     bindAddr,
					"bind_port":     bindPort,
					logrus.ErrorKey: err,
				}).Error("Failed to open forwarded-tcpip channel.")
				return
			}
			defer channel.Close()

			go gossh.DiscardRequests(requests)

			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   bindAddr,
				"bind_port":   bindPort,
			}).Info("Proxying traffic for remote forwarded connection.")

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				io.Copy(channel, conn)
				channel.CloseWrite()
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, channel)
				// conn.CloseWrite() // Not needed as defer conn.Close() handles it
			}()

			wg.Wait()
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   bindAddr,
				"bind_port":   bindPort,
			}).Info("Remote forwarded proxying finished.")
		}()
	}
}
