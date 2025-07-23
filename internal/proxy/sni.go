package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"zcdns-tunnel/internal/tunnel"
)

// SNIProxy handles routing TLS connections based on the SNI hostname.
// It now also acts as a multiplexer for HTTP and a default TCP proxy.
type SNIProxy struct {
	Manager    *tunnel.Manager
	ListenAddr string
	listener   net.Listener
	listenerMu sync.Mutex

	// For default TCP proxying
	defaultTCPBackendAddr string
	defaultTCPBackendMu   sync.RWMutex
}

// NewSNIProxy creates a new SNIProxy handler.
func NewSNIProxy(manager *tunnel.Manager, listenAddr string) *SNIProxy {
	return &SNIProxy{
		Manager:    manager,
		ListenAddr: listenAddr,
	}
}

// SetDefaultTCPBackend sets the default backend for non-SNI/HTTP traffic.
// Returns true if the default was set, false if one was already present.
func (p *SNIProxy) SetDefaultTCPBackend(addr string) bool {
	p.defaultTCPBackendMu.Lock()
	defer p.defaultTCPBackendMu.Unlock()
	if p.defaultTCPBackendAddr != "" {
		return false // A default backend is already set
	}
	p.defaultTCPBackendAddr = addr
	logrus.WithFields(logrus.Fields{
		"listen_addr":  p.ListenAddr,
		"backend_addr": addr,
	}).Info("Set default TCP backend for shared listener")
	return true
}

// ClearDefaultTCPBackend removes the default backend if it matches the provided address.
func (p *SNIProxy) ClearDefaultTCPBackend(addr string) {
	p.defaultTCPBackendMu.Lock()
	defer p.defaultTCPBackendMu.Unlock()
	if p.defaultTCPBackendAddr == addr {
		logrus.WithFields(logrus.Fields{
			"listen_addr":  p.ListenAddr,
			"backend_addr": addr,
		}).Info("Clearing default TCP backend for shared listener")
		p.defaultTCPBackendAddr = ""
	}
}

// GetListenPort waits for the listener to be initialized and returns the actual listening port.
func (p *SNIProxy) GetListenPort(timeout time.Duration) (uint32, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return 0, fmt.Errorf("timed out waiting for listener to start on %s", p.ListenAddr)
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

// ListenAndServe starts the SNI proxy listener.
func (p *SNIProxy) ListenAndServe(ctx context.Context) error {
	logrus.Printf("Starting multiplexer proxy server on %s", p.ListenAddr)

	listener, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.ListenAddr, err)
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
		logrus.Printf("Shutting down multiplexer proxy server on %s...", p.ListenAddr)
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
					logrus.WithFields(logrus.Fields{
						logrus.ErrorKey: err,
						"listen_addr":   p.ListenAddr,
					}).Error("Failed to accept connection")
					return err
				}
				continue
			}
		}
		go p.handleConnectionMultiplex(conn)
	}
}

func isTemporary(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return true
	}
	return false
}

// handleConnectionMultiplex sniffs the protocol and delegates to the appropriate handler.
func (p *SNIProxy) handleConnectionMultiplex(conn net.Conn) {
	// We need a connection that can have bytes put back
	prefixedConn := newPrefixedConn(conn, bufio.NewReader(conn))

	// 1. Check for a default backend first for non-TLS traffic.
	p.defaultTCPBackendMu.RLock()
	backendAddr := p.defaultTCPBackendAddr
	p.defaultTCPBackendMu.RUnlock()

	// Peek to check for TLS
	peeked, err := prefixedConn.r.Peek(1)
	if err != nil {
		// If peeking fails, it's definitely not TLS.
		// If a default backend exists, send it there. Otherwise, close.
		if backendAddr != "" {
			p.handleDefaultTCPConnection(prefixedConn)
		} else {
			prefixedConn.Close()
		}
		return
	}

	// 2. Handle TLS traffic (highest priority)
	if peeked[0] == 0x16 {
		p.handleTLSConnection(prefixedConn)
		return
	}

	// 3. If it's not TLS and a default backend exists, use it.
	// This is the key logic fix: we prioritize the default backend over HTTP routing.
	if backendAddr != "" {
		p.handleDefaultTCPConnection(prefixedConn)
		return
	}

	// 4. ONLY if no default backend exists, try to handle as HTTP.
	p.handleHTTPConnection(prefixedConn)
}

// handleDefaultTCPConnection handles plain TCP traffic by proxying to the default backend.
func (p *SNIProxy) handleDefaultTCPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	p.defaultTCPBackendMu.RLock()
	backendAddr := p.defaultTCPBackendAddr
	p.defaultTCPBackendMu.RUnlock()

	if backendAddr == "" {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Generic TCP traffic received but no default backend is set. Closing connection.")
		return
	}

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":  clientConn.RemoteAddr(),
			"backend_addr": backendAddr,
			logrus.ErrorKey: err,
		}).Error("Failed to connect to default TCP backend")
		return
	}
	defer backendConn.Close()

	logrus.WithFields(logrus.Fields{
		"remote_addr":  clientConn.RemoteAddr(),
		"backend_addr": backendAddr,
	}).Info("Proxying generic TCP traffic to default backend")

	proxyData(clientConn, backendConn)
}

// handleTLSConnection handles TLS traffic by extracting the SNI and proxying.
func (p *SNIProxy) handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()

	var sniHost string
	err := tls.Server(clientConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniHost = hello.ServerName
			// Return a dummy error to stop the handshake after getting the SNI
			return nil, fmt.Errorf("just-a-trick-to-get-sni")
		},
	}).Handshake()

	// We expect the "trick" error, any other error is a problem.
	if err != nil && !strings.Contains(err.Error(), "just-a-trick-to-get-sni") {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to extract SNI from TLS handshake")
		return
	}

	if sniHost == "" {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("SNI hostname not found in TLS handshake")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":  clientConn.RemoteAddr(),
		"sni_hostname": sniHost,
	}).Info("Extracted SNI hostname")

	sshConn, ok := p.Manager.LoadClient(sniHost)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": sniHost}).Error("Tunnel for domain not found")
		return
	}

	p.proxyToSSHChannel(clientConn, sshConn, sniHost)
}

// handleHTTPConnection handles plain HTTP traffic by proxying.
func (p *SNIProxy) handleHTTPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// We need a buffered reader to read the request
	buffReader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(buffReader)
	if err != nil {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to read HTTP request")
		return
	}

	domain := req.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"source_ip":   clientConn.RemoteAddr(),
		"request_uri": req.RequestURI,
	}).Info("Identified HTTP request")

	sshConn, ok := p.Manager.LoadClient(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Tunnel for domain not found")
		return
	}

	// Re-wrap the connection with the buffered reader to ensure no data is lost
	prefixedConn := newPrefixedConn(clientConn, buffReader)
	p.proxyToSSHChannel(prefixedConn, sshConn, domain)
}

// proxyToSSHChannel finds the correct SSH client for a domain and proxies the connection.
func (p *SNIProxy) proxyToSSHChannel(clientConn net.Conn, sshConn ssh.Conn, domain string) {
	// Get the port that was confirmed to the client for this domain.
	boundPort, ok := p.Manager.LoadUserBindingPort(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Could not find the bound port for the domain. This should not happen.")
		return
	}

	originatorIP, originatorPortStr, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	originatorPort, _ := strconv.Atoi(originatorPortStr)

	payload := ssh.Marshal(&struct {
		ConnectedAddr  string
		ConnectedPort  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		ConnectedAddr:  "0.0.0.0", // The address the client requested to bind to
		ConnectedPort:  boundPort, // The port the server *confirmed* to the client
		OriginatorIP:   originatorIP,
		OriginatorPort: uint32(originatorPort),
	})

	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		logrus.WithFields(logrus.Fields{"domain": domain}).WithError(err).Error("Failed to open 'forwarded-tcpip' SSH channel")
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"remote_addr": clientConn.RemoteAddr(),
	}).Info("Proxying traffic to SSH channel")

	proxyData(clientConn, channel)
}

// proxyData copies data between two connections and logs the process.
func proxyData(client, target io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer target.Close()
		io.Copy(target, client)
	}()

	go func() {
		defer wg.Done()
		defer client.Close()
		io.Copy(client, target)
	}()

	wg.Wait()
}

// prefixedConn is a helper struct that allows us to "put back" bytes
// that were peeked from a connection.
type prefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func newPrefixedConn(conn net.Conn, r *bufio.Reader) *prefixedConn {
	return &prefixedConn{
		Conn: conn,
		r:    r,
	}
}

func (c *prefixedConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}
