package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// TCPProxy handles raw TCP packet forwarding for a single SSH connection.
// It is used as the intermediary bridge between the shared SNIProxy and the
// specific SSH client connection that owns a domain.
type TCPProxy struct {
	ListenAddr     string // The address this proxy listens on (e.g., 127.0.0.1:12345)
	PublicPort     uint32 // The public port the user originally requested (e.g., 80)
	ConnectedAddr  string // The address the client originally requested to bind to (usually IP publik node)
	sshConn        *ssh.ServerConn
	listener       net.Listener
	listenerMu     sync.Mutex
}

// NewTCPProxy creates a new TCPProxy handler for a specific SSH connection.
func NewTCPProxy(listenAddr string, publicPort uint32, connectedAddr string, sshConn *ssh.ServerConn) *TCPProxy {
	// Log untuk debugging
	logrus.Infof("Creating new TCPProxy with ConnectedAddr: %s", connectedAddr)
	
	return &TCPProxy{
		ListenAddr:     listenAddr,
		PublicPort:     publicPort,
		ConnectedAddr:  connectedAddr,
		sshConn:        sshConn,
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

	// Log untuk debugging
	logrus.Infof("Creating SSH payload with ConnectedAddr: %s", p.ConnectedAddr)

	// Check if this is a direct SSH connection
	if strings.HasPrefix(p.ConnectedAddr, "DIRECT_SSH:") {
		// Extract the target host and port from the direct SSH address
		parts := strings.Split(p.ConnectedAddr, ":")
		if len(parts) >= 3 {
			targetHost := parts[1]
			targetPortStr := parts[2]
			targetPort, err := strconv.Atoi(targetPortStr)
			if err != nil {
				logrus.WithError(err).Errorf("Failed to parse direct SSH port: %s", targetPortStr)
				return
			}
			
			logrus.WithFields(logrus.Fields{
				"target_host": targetHost,
				"target_port": targetPort,
				"remote_addr": conn.RemoteAddr(),
			}).Info("Attempting direct SSH connection to responsible node")
			
			// Establish a direct TCP connection to the target
			targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
			targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				logrus.WithError(err).Errorf("Failed to establish direct SSH connection to %s", targetAddr)
				return
			}
			defer targetConn.Close()
			
			logrus.WithFields(logrus.Fields{
				"target_addr": targetAddr,
				"remote_addr": conn.RemoteAddr(),
			}).Info("Successfully established direct SSH connection to responsible node")
			
			// Proxy data between the client and the target
			go func() {
				_, err := io.Copy(targetConn, conn)
				if err != nil && err != io.EOF {
					logrus.WithError(err).Error("Error copying data from client to target")
				}
			}()
			
			_, err = io.Copy(conn, targetConn)
			if err != nil && err != io.EOF {
				logrus.WithError(err).Error("Error copying data from target to client")
			}
			
			return
		}
	}

	// Regular SSH channel forwarding
	payload := ssh.Marshal(&struct {
		ConnectedAddr  string
		ConnectedPort  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		ConnectedAddr:  p.ConnectedAddr, // Menggunakan alamat yang disimpan saat inisialisasi
		ConnectedPort:  p.PublicPort,
		OriginatorIP:   originatorIP,
		OriginatorPort: uint32(originatorPort),
	})

	channel, reqs, err := p.sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"public_port": p.PublicPort,
		}).WithError(err).Error("Failed to open 'forwarded-tcpip' SSH channel for bridge")
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	logrus.WithFields(logrus.Fields{
		"public_port": p.PublicPort,
		"remote_addr": conn.RemoteAddr(),
	}).Info("Proxying bridged TCP connection to SSH channel")

	proxyData(conn, channel)
}
