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

// SSHServer represents the SSH server for managing tunnels.
type SSHServer struct {
	Config   config.ServerConfig
	listener net.Listener
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

	go gossh.DiscardRequests(reqs)

	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel)
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Info("SSH connection closed.")
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

	if newChannel.ChannelType() != "direct-tcpip" {
		logrus.WithFields(logrus.Fields{
			"remote_addr":  sshConn.RemoteAddr(),
			"channel_type": newChannel.ChannelType(),
		}).Warn("Unsupported channel type")
		newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
		return
	}

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
	backendAddr := fmt.Sprintf("%s:%d", req.HostToConnect, req.PortToConnect)

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
}