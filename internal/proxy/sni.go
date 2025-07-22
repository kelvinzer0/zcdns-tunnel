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
// It now also acts as a multiplexer for HTTP traffic.
type SNIProxy struct {
	Manager    *tunnel.Manager
	ListenAddr string
	listener   net.Listener
	listenerMu sync.Mutex
}

// NewSNIProxy creates a new SNIProxy handler.
func NewSNIProxy(manager *tunnel.Manager, listenAddr string) *SNIProxy {
	return &SNIProxy{
		Manager:    manager,
		ListenAddr: listenAddr,
	}
}

// GetListenPort waits for the listener to be initialized and returns the actual listening port.
// This is crucial for handling dynamic port allocation (when listenAddr is ":0").
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
			// Check if the context was cancelled, which would cause Accept to fail.
			select {
			case <-ctx.Done():
				return nil // Graceful shutdown.
			default:
				logrus.WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"listen_addr":   p.ListenAddr,
				}).Error("Failed to accept connection")
				// If the listener is closed, we should stop.
				if !isTemporary(err) {
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
	defer conn.Close()

	buffReader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	peeked, err := buffReader.Peek(8)
	if err != nil {
		if err != io.EOF && !strings.Contains(err.Error(), "short read") {
			logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Debug("Failed to peek connection for protocol sniffing")
		}
		return
	}
	conn.SetReadDeadline(time.Time{})

	if peeked[0] == 0x16 {
		p.handleTLSConnection(conn, buffReader)
		return
	}

	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range httpMethods {
		if strings.HasPrefix(string(peeked), method) {
			p.handleHTTPConnection(conn, buffReader)
			return
		}
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": conn.RemoteAddr(),
		"peeked_data": string(peeked),
	}).Warn("Unknown protocol detected. Closing connection.")
}

// handleTLSConnection handles TLS traffic by extracting the SNI and proxying.
func (p *SNIProxy) handleTLSConnection(conn net.Conn, buffReader *bufio.Reader) {
	prefixedConn := newPrefixedConn(conn, buffReader)

	var sniHost string
	err := tls.Server(prefixedConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniHost = hello.ServerName
			return nil, fmt.Errorf("just-a-trick-to-get-sni")
		},
	}).Handshake()

	if err != nil && !strings.Contains(err.Error(), "just-a-trick-to-get-sni") {
		logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Warn("Failed to extract SNI from TLS handshake")
		return
	}

	if sniHost == "" {
		logrus.WithField("remote_addr", conn.RemoteAddr()).Warn("SNI hostname not found in TLS handshake")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":  conn.RemoteAddr(),
		"sni_hostname": sniHost,
	}).Info("Extracted SNI hostname")

	p.proxyToSSHChannel(prefixedConn, sniHost)
}

// handleHTTPConnection handles plain HTTP traffic by proxying.
func (p *SNIProxy) handleHTTPConnection(conn net.Conn, buffReader *bufio.Reader) {
	prefixedConn := newPrefixedConn(conn, buffReader)

	req, err := http.ReadRequest(buffReader)
	if err != nil {
		logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Warn("Failed to read HTTP request")
		return
	}

	domain := req.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"source_ip":   conn.RemoteAddr(),
		"request_uri": req.RequestURI,
	}).Info("Identified HTTP request")

	p.proxyToSSHChannel(prefixedConn, domain)
}

// proxyToSSHChannel finds the correct SSH client for a domain and proxies the connection.
func (p *SNIProxy) proxyToSSHChannel(conn net.Conn, domain string) {
	sshConn, ok := p.Manager.LoadClient(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Tunnel for domain not found")
		return
	}

	// Get the port that was confirmed to the client for this domain.
	boundPort, ok := p.Manager.LoadUserBindingPort(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Could not find the bound port for the domain. This should not happen.")
		return
	}

	originatorIP, originatorPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
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
		"remote_addr": conn.RemoteAddr(),
	}).Info("Proxying traffic to SSH channel")

	proxyData(conn, channel)
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
