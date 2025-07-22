package server

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/auth"
	"zcdns-tunnel/internal/config"
	channelHandlers "zcdns-tunnel/internal/ssh/channel"
	"zcdns-tunnel/internal/tunnel"
)

// SSHServer represents the SSH server for managing tunnels.
type SSHServer struct {
	Config  config.ServerConfig
	Manager *tunnel.Manager
}

// NewSSHServer creates a new SSH server instance.
func NewSSHServer(cfg config.ServerConfig) *SSHServer {
	return &SSHServer{
		Config:  cfg,
		Manager: tunnel.NewManager(),
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

	// Store the active client connection by domain
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if ok && domain != "" {
		s.Manager.StoreClient(domain, sshConn)
	}

	// Handle global requests (e.g., tcpip-forward for -R)
	go s.handleGlobalRequests(sshConn, reqs)

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
		channelHandlers.HandleDirectTCPIP(sshConn, newChannel)
	case "forwarded-tcpip":
		channelHandlers.HandleForwardedTCPIP(sshConn, newChannel)
	case "session":
		channelHandlers.HandleSession(sshConn, newChannel)
	default:
		channelHandlers.HandleUnsupportedChannel(sshConn, newChannel)
	}
}
