package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/config"
)

// remoteForwardedPort represents a port opened for remote forwarding on the server.
type remoteForwardedPort struct {
	listener net.Listener
	sshConn  *gossh.ServerConn
}

// SSHServer represents the SSH server for managing tunnels.
type SSHServer struct {
	Config   config.ServerConfig
	listener net.Listener
	// remoteListeners maps "bind_addr:bind_port" to remoteForwardedPort
	remoteListeners sync.Map
}

// NewSSHServer creates a new SSH server instance.
func NewSSHServer(cfg config.ServerConfig) *SSHServer {
	return &SSHServer{Config: cfg}
}

// StartSSHServer starts the SSH listener.
func (s *SSHServer) StartSSHServer(ctx context.Context) error {
	logrus.Printf("Starting SSH listener on %s", s.Config.SshListenAddr)

	privateBytes, err := os.ReadFile(s.Config.SshHostKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load SSH private key: %w", err)
	}

	private, err := gossh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	sshConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			domain := conn.User()
			logrus.WithFields(logrus.Fields{
				"remote_addr": conn.RemoteAddr(),
				"domain":      domain,
			}).Info("SSH: Auth attempt")

			// CNAME validation
			cname, err := net.LookupCNAME(domain)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": conn.RemoteAddr(),
					"domain":      domain,
					logrus.ErrorKey: err,
				}).Warn("SSH: Failed to lookup CNAME for domain")
				return nil, fmt.Errorf("failed to lookup CNAME")
			}

			// The CNAME must point to the validation domain.
			// The CNAME lookup often returns a final, non-alias record, so we check if the result
			// is the validation domain itself (with a trailing dot).
			if !strings.HasSuffix(cname, s.Config.ValidationDomain+".") {
				logrus.WithFields(logrus.Fields{
					"remote_addr":      conn.RemoteAddr(),
					"domain":           domain,
					"cname_found":      cname,
					"expected_domain":  s.Config.ValidationDomain,
				}).Warn("SSH: CNAME validation failed")
				return nil, fmt.Errorf("CNAME validation failed")
			}

			// TXT record for public key
			txtRecords, err := net.LookupTXT(domain)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": conn.RemoteAddr(),
					"domain":      domain,
					logrus.ErrorKey: err,
				}).Warn("SSH: Failed to lookup TXT record for domain")
				return nil, fmt.Errorf("failed to lookup TXT record")
			}

			for _, record := range txtRecords {
				if strings.HasPrefix(record, "zcdns-ssh-key=") {
					parts := strings.SplitN(record, "=", 2)
					if len(parts) == 2 {
						authKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(parts[1]))
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"remote_addr": conn.RemoteAddr(),
								"domain":      domain,
								logrus.ErrorKey: err,
							}).Warn("SSH: Failed to parse public key from TXT record")
							continue
						}
						if bytes.Equal(key.Marshal(), authKey.Marshal()) {
							logrus.WithFields(logrus.Fields{
								"remote_addr": conn.RemoteAddr(),
								"domain":      domain,
							}).Info("SSH: Public key authenticated successfully")
							return &gossh.Permissions{
								Extensions: map[string]string{
									"domain": domain,
								},
							}, nil
						}
					}
				}
			}

			logrus.WithFields(logrus.Fields{
				"remote_addr": conn.RemoteAddr(),
				"domain":      domain,
			}).Warn("SSH: Public key authentication failed")
			return nil, fmt.Errorf("public key authentication failed")
		},
	}
	sshConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", s.Config.SshListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen for SSH connections: %w", err)
	}
	s.listener = listener

	go func() {
		<-ctx.Done()
		logrus.Println("Shutting down SSH server listener...")
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				logrus.Println("SSH server listener closed.")
				return nil
			default:
				logrus.WithFields(logrus.Fields{
					logrus.ErrorKey: err,
				}).Error("Failed to accept SSH connection")
				continue
			}
		}
		go s.handleSSHConnection(conn, sshConfig)
	}
}

func (s *SSHServer) handleSSHConnection(conn net.Conn, sshConfig *gossh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := gossh.NewServerConn(conn, sshConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr": conn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to handshake SSH")
		return
	}
	logrus.WithFields(logrus.Fields{
		"remote_addr":    sshConn.RemoteAddr(),
		"client_version": string(sshConn.ClientVersion()),
	}).Info("New SSH connection")

	// Handle global requests (e.g., tcpip-forward for -R)
	go s.handleGlobalRequests(sshConn, reqs)

	// Service the incoming channels (e.g., direct-tcpip for -L, forwarded-tcpip for -R)
	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel)
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Info("SSH connection closed.")

	// Clean up any remote forwarded listeners associated with this SSH connection
	s.remoteListeners.Range(func(key, value interface{}) bool {
		if rfPort, ok := value.(*remoteForwardedPort); ok && rfPort.sshConn == sshConn {
			logrus.WithFields(logrus.Fields{
				"bind_addr_port": key,
			}).Info("Closing remote forwarded listener on SSH connection close.")
			rfPort.listener.Close()
			s.remoteListeners.Delete(key)
		}
		return true
	})
}

func (s *SSHServer) handleGlobalRequests(sshConn *gossh.ServerConn, reqs <-chan *gossh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			addr := net.JoinHostPort(payload.BindAddr, fmt.Sprintf("%d", payload.BindPort))
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   payload.BindAddr,
				"bind_port":   payload.BindPort,
			}).Info("Received tcpip-forward request")

			// Check if port is already in use or reserved
			if _, loaded := s.remoteListeners.LoadOrStore(addr, nil); loaded {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					"bind_addr_port": addr,
				}).Warn("Port already in use for remote forwarding.")
				req.Reply(false, nil)
				continue
			}

			listener, err := net.Listen("tcp", addr)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					"bind_addr_port": addr,
					logrus.ErrorKey: err,
				}).Error("Failed to listen for remote forwarding")
				s.remoteListeners.Delete(addr) // Clean up the nil entry
				req.Reply(false, nil)
				continue
			}

			s.remoteListeners.Store(addr, &remoteForwardedPort{listener: listener, sshConn: sshConn})
			req.Reply(true, nil)
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr_port": addr,
			}).Info("Successfully opened remote forwarded port.")

			// Start accepting connections on this new listener
			go s.handleRemoteForwardedConnections(sshConn, listener, payload.BindAddr, payload.BindPort)

		case "cancel-tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal cancel-tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			addr := net.JoinHostPort(payload.BindAddr, fmt.Sprintf("%d", payload.BindPort))
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr_port": addr,
			}).Info("Received cancel-tcpip-forward request")

			if rfPort, loaded := s.remoteListeners.LoadAndDelete(addr); loaded {
				if p, ok := rfPort.(*remoteForwardedPort); ok {
					p.listener.Close()
					logrus.WithFields(logrus.Fields{
						"remote_addr": sshConn.RemoteAddr(),
						"bind_addr_port": addr,
					}).Info("Successfully closed remote forwarded port.")
					req.Reply(true, nil)
				} else {
					logrus.WithFields(logrus.Fields{
						"remote_addr": sshConn.RemoteAddr(),
						"bind_addr_port": addr,
					}).Error("Type assertion failed for remote forwarded port.")
					req.Reply(false, nil)
				}
			} else {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					"bind_addr_port": addr,
				}).Warn("Remote forwarded port not found for cancellation.")
				req.Reply(false, nil)
			}

		default:
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"request_type": req.Type,
			}).Warn("Unknown global request type")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *SSHServer) handleRemoteForwardedConnections(sshConn *gossh.ServerConn, listener net.Listener, bindAddr string, bindPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed, or other error. Log and exit.
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   bindAddr,
				"bind_port":   bindPort,
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
				ConnectedAddr   string
				ConnectedPort   uint32
				OriginatorIP    string
				OriginatorPort  uint32
			}{
				ConnectedAddr:  bindAddr,
				ConnectedPort:  bindPort,
				OriginatorIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
				OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
			}))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr": sshConn.RemoteAddr(),
					"bind_addr":   bindAddr,
					"bind_port":   bindPort,
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

func (s *SSHServer) handleChannel(sshConn *gossh.ServerConn, newChannel gossh.NewChannel) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Error("No domain found in SSH connection permissions")
		newChannel.Reject(gossh.Prohibited, "internal server error")
		return
	}

	switch newChannel.ChannelType() {
	case "direct-tcpip":
		var req struct {
			HostToConnect  string
			PortToConnect  uint32
			OriginatorIP   string
			OriginatorPort uint32
		}
		if err := gossh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				logrus.ErrorKey: err,
			}).Error("Failed to unmarshal direct-tcpip request")
			newChannel.Reject(gossh.Prohibited, "invalid payload")
			return
		}

		logrus.WithFields(logrus.Fields{
			"remote_addr":     sshConn.RemoteAddr(),
			"domain":          domain,
			"target_host":     req.HostToConnect,
			"target_port":     req.PortToConnect,
			"originator_ip":   req.OriginatorIP,
			"originator_port": req.OriginatorPort,
		}).Info("Received direct-tcpip request")

		// The backend address is now determined by the client's request.
		backendAddr := net.JoinHostPort(req.HostToConnect, fmt.Sprintf("%d", req.PortToConnect))

		backendConn, err := net.Dial("tcp", backendAddr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"remote_addr":  sshConn.RemoteAddr(),
				"domain":       domain,
				"backend_addr": backendAddr,
				logrus.ErrorKey:  err,
			}).Error("Failed to connect to backend")
			newChannel.Reject(gossh.ConnectionFailed, "failed to connect to backend")
			return
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				logrus.ErrorKey: err,
			}).Error("Could not accept channel")
			backendConn.Close()
			return
		}
		go gossh.DiscardRequests(requests)

		logrus.WithFields(logrus.Fields{
			"remote_addr":  sshConn.RemoteAddr(),
			"domain":       domain,
			"backend_addr": backendAddr,
		}).Info("Proxying traffic")

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			defer channel.Close()
			defer backendConn.Close()
			io.Copy(channel, backendConn)
		}()
		go func() {
			defer wg.Done()
			defer channel.Close()
			defer backendConn.Close()
			io.Copy(backendConn, channel)
		}()

		wg.Wait()
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
			"domain":      domain,
		}).Info("Proxying finished")

	case "session":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received session channel. Rejecting.")
		newChannel.Reject(gossh.Prohibited, "session channels not allowed")
		return
	case "x11":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received X11 channel. Rejecting.")
		newChannel.Reject(gossh.Prohibited, "X11 channels not allowed")
		return
	case "auth-agent@openssh.com":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received auth-agent channel. Rejecting.")
		newChannel.Reject(gossh.Prohibited, "auth-agent channels not allowed")
		return
	default:
		logrus.WithFields(logrus.Fields{
			"remote_addr":  sshConn.RemoteAddr(),
			"channel_type": newChannel.ChannelType(),
		}).Warn("Unknown channel type. Rejecting.")
		newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
		return
	}
}
