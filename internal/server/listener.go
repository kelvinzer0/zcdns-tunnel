package server

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"
)

// SSHListener is responsible for listening for new SSH connections.
type SSHListener struct {
	addr     string
	config   *ssh.ServerConfig
	listener net.Listener
}

// NewSSHListener creates a new SSHListener.
func NewSSHListener(addr string, config *ssh.ServerConfig) *SSHListener {
	return &SSHListener{
		addr:     addr,
		config:   config,
	}
}

// ListenAndServe starts the SSH listener and accepts connections.
// It calls the provided handler function for each new connection.
func (l *SSHListener) ListenAndServe(ctx context.Context, handler func(net.Conn, *ssh.ServerConfig)) error {
	logrus.Printf("Starting SSH listener on %s", l.addr)

	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to listen for SSH connections: %w", err)
	}
	l.listener = listener

	go func() {
		<-ctx.Done()
		logrus.Println("Shutting down SSH listener...")
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				logrus.Println("SSH listener closed.")
				return nil
			default:
				logrus.WithFields(logrus.Fields{
					logrus.ErrorKey: err,
				}).Error("Failed to accept SSH connection")
				continue
			}
		}
		go handler(conn, l.config)
	}
}
