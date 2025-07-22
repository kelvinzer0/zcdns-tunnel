package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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
	mu         sync.Mutex
}

// NewSNIProxy creates a new SNIProxy handler.
func NewSNIProxy(manager *tunnel.Manager, listenAddr string) *SNIProxy {
	return &SNIProxy{
		Manager:    manager,
		ListenAddr: listenAddr,
	}
}

// ListenAndServe starts the SNI proxy listener.
func (p *SNIProxy) ListenAndServe(ctx context.Context) error {
	logrus.Printf("Starting multiplexer proxy server on %s", p.ListenAddr)

	listener, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.ListenAddr, err)
	}
	p.listener = listener // Store the listener

	go func() {
		<-ctx.Done()
		logrus.Printf("Shutting down multiplexer proxy server on %s...", p.ListenAddr)
		p.listener.Close()
	}()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logrus.WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"listen_addr":   p.ListenAddr,
				}).Error("Failed to accept connection")
				continue
			}
		}
		go p.handleConnectionMultiplex(conn)
	}
}

// handleConnectionMultiplex sniffs the protocol and delegates to the appropriate handler.
func (p *SNIProxy) handleConnectionMultiplex(conn net.Conn) {
	defer conn.Close()

	// Use a buffered reader to peek at the initial bytes.
	buffReader := bufio.NewReader(conn)
	
	// Set a deadline for peeking to prevent slow clients from holding resources.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	// Peek at the first few bytes to determine the protocol.
	// We peek up to 8 bytes, which is enough to identify common HTTP methods.
	peeked, err := buffReader.Peek(8)
	if err != nil {
		if err != io.EOF && !strings.Contains(err.Error(), "short read") {
			logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Debug("Failed to peek connection for protocol sniffing")
		}
		return
	}

	// Reset the deadline after peeking.
	conn.SetReadDeadline(time.Time{})

	// --- Protocol Detection Logic ---

	// 1. Check for TLS Handshake (most specific)
	if peeked[0] == 0x16 {
		p.handleTLSConnection(conn, buffReader)
		return
	}

	// 2. Check for valid HTTP Methods (explicit identification)
	// We convert the peeked bytes to a string for easy comparison.
	peekedStr := string(peeked)
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range httpMethods {
		if strings.HasPrefix(peekedStr, method) {
			p.handleHTTPConnection(conn, buffReader)
			return
		}
	}

	// 3. If neither, it's an unknown protocol.
	logrus.WithFields(logrus.Fields{
		"remote_addr": conn.RemoteAddr(),
		"peeked_data": string(peeked),
	}).Warn("Unknown protocol detected. Closing connection.")
}

// handleTLSConnection handles TLS traffic by extracting the SNI and proxying.
func (p *SNIProxy) handleTLSConnection(conn net.Conn, buffReader *bufio.Reader) {
	// We need a connection that can have bytes put back into its buffer.
	prefixedConn := newPrefixedConn(conn, buffReader)

	var sniHost string
	// Use the standard library to parse the ClientHello and get the SNI.
	// This is much more robust than a manual parser.
	err := tls.Server(prefixedConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniHost = hello.ServerName
			// We return an error to stop the handshake after getting the SNI.
			// We don't want to actually terminate TLS here, just get the name.
			return nil, fmt.Errorf("just-a-trick-to-get-sni")
		},
	}).Handshake()

	// We expect the "just-a-trick-to-get-sni" error. Any other error is a problem.
	if err != nil && !strings.Contains(err.Error(), "just-a-trick-to-get-sni") {
		logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Warn("Failed to extract SNI from TLS handshake")
		return
	}

	if sniHost == "" {
		logrus.WithField("remote_addr", conn.RemoteAddr()).Warn("SNI hostname not found in TLS handshake")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": conn.RemoteAddr(),
		"sni_hostname": sniHost,
	}).Info("Extracted SNI hostname")

	// Now that we have the SNI, find the corresponding SSH client.
	sshConn, ok := p.Manager.LoadClient(sniHost)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": sniHost}).Error("Tunnel for SNI domain not found")
		return
	}

	// Open a direct-tcpip channel back to the SSH client.
	// The destination host/port are placeholders as the client knows where to forward.
	channel, reqs, err := sshConn.OpenChannel("direct-tcpip", ssh.Marshal(&struct{
		HostToConnect  string
		PortToConnect  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		HostToConnect:  "localhost", // Placeholder
		PortToConnect:  0,           // Placeholder
		OriginatorIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
	}))
	if err != nil {
		logrus.WithFields(logrus.Fields{"domain": sniHost}).WithError(err).Error("Failed to open SSH channel for SNI proxy")
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	logrus.WithFields(logrus.Fields{
		"remote_addr":  conn.RemoteAddr(),
		"sni_hostname": sniHost,
	}).Info("Proxying TLS connection")

	// Proxy data between the incoming connection and the SSH channel.
	proxyData(prefixedConn, channel)
}

// handleHTTPConnection handles plain HTTP traffic by using a reverse proxy.
func (p *SNIProxy) handleHTTPConnection(conn net.Conn, buffReader *bufio.Reader) {
	// Read the HTTP request from the buffered reader.
	req, err := http.ReadRequest(buffReader)
	if err != nil {
		logrus.WithField("remote_addr", conn.RemoteAddr()).WithError(err).Warn("Failed to read HTTP request")
		return
	}

	domain := req.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	// Find the SSH client for this domain.
	sshConn, ok := p.Manager.LoadClient(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Tunnel for HTTP domain not found")
		// Send a proper HTTP error response.
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(strings.NewReader("Tunnel not available")),
		}
		resp.Write(conn)
		return
	}

	// The reverse proxy will be handled by the SSH client, which forwards to its local service.
	// We just need to stream the request over the channel.
	channel, reqs, err := sshConn.OpenChannel("direct-tcpip", ssh.Marshal(&struct{
		HostToConnect  string
		PortToConnect  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		HostToConnect:  "localhost", // Placeholder
		PortToConnect:  80,          // Placeholder, can indicate HTTP
		OriginatorIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
	}))
	if err != nil {
		logrus.WithFields(logrus.Fields{"domain": domain}).WithError(err).Error("Failed to open SSH channel for HTTP proxy")
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"source_ip":   conn.RemoteAddr(),
		"request_uri": req.RequestURI,
	}).Info("Forwarding HTTP request")

	// Write the original request to the SSH channel.
	err = req.Write(channel)
	if err != nil {
		logrus.WithFields(logrus.Fields{"domain": domain}).WithError(err).Error("Failed to write HTTP request to SSH channel")
		return
	}

	// Copy the response from the SSH channel back to the client.
	io.Copy(conn, channel)
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
// that were peeked from a connection, so the next reader (like a TLS handshake
// or an HTTP parser) gets the full, original stream.
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
