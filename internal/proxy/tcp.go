package proxy

import (
	"context"
	"fmt"

	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// TCPProxy handles raw TCP packet forwarding for a single SSH connection.
// It does not perform any protocol sniffing.
type TCPProxy struct {
	ListenAddr string
	sshConn    *ssh.ServerConn
	listener   net.Listener
	listenerMu sync.Mutex
}

// NewTCPProxy creates a new TCPProxy handler for a specific SSH connection.
func NewTCPProxy(listenAddr string, sshConn *ssh.ServerConn) *TCPProxy {
	return &TCPProxy{
		ListenAddr: listenAddr,
		sshConn:    sshConn,
	}
}

// GetListenPort waits for the listener to be initialized and returns the actual listening port.
func (p *TCPProxy) GetListenPort(timeout time.Duration) (uint32, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return 0, fmt.Errorf("timed out waiting for TCP listener to start on %s", p.ListenAddr)
		case <-ticker.C:
			p.listenerMu.Lock()
			listener := p.listener
			p.listenerMu.Unlock()
			if listener != nil {
				return uint32(listener.Addr().(*net.TCPAddr).Port), nil
			}
		}
	}
}

// ListenAndServe starts the raw TCP proxy listener.
func (p *TCPProxy) ListenAndServe(ctx context.Context) error {
	logrus.Printf("Starting raw TCP proxy server on %s", p.ListenAddr)

	listener, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen for TCP on %s: %w", p.ListenAddr, err)
	}

	p.listenerMu.Lock()
	p.listener = listener
	p.listenerMu.Unlock()

	defer func() {
		p.listenerMu.Lock()
		p.listener.Close()
		p.listener = nil
		p.listenerMu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		logrus.Printf("Shutting down raw TCP proxy server on %s...", p.ListenAddr)
		p.listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil // Graceful shutdown.
			default:
				// If the listener is closed, we should stop.
				if !isTemporary(err) {
					return err
				}
				continue
			}
		}
		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	originatorIP, originatorPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	originatorPort, _ := strconv.Atoi(originatorPortStr)

	listenHost, listenPortStr, _ := net.SplitHostPort(p.listener.Addr().String())
	listenPort, _ := strconv.Atoi(listenPortStr)

	payload := ssh.Marshal(&struct {
		ConnectedAddr  string
		ConnectedPort  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		ConnectedAddr:  listenHost,
		ConnectedPort:  uint32(listenPort),
		OriginatorIP:   originatorIP,
		OriginatorPort: uint32(originatorPort),
	})

	channel, reqs, err := p.sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"listen_addr": p.ListenAddr,
		}).WithError(err).Error("Failed to open 'forwarded-tcpip' SSH channel for raw TCP proxy")
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	logrus.WithFields(logrus.Fields{
		"listen_addr": p.ListenAddr,
		"remote_addr": conn.RemoteAddr(),
	}).Info("Proxying raw TCP connection to SSH channel")

	proxyData(conn, channel)
}
