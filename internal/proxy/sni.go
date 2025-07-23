package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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

// HasDefaultTCPBackend returns true if a default backend is currently configured.
func (p *SNIProxy) HasDefaultTCPBackend() bool {
	p.defaultTCPBackendMu.RLock()
	defer p.defaultTCPBackendMu.RUnlock()
	return p.defaultTCPBackendAddr != ""
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

	// Peek to check for TLS
	peeked, err := prefixedConn.r.Peek(1)
	if err != nil {
		// If peeking fails, it's definitely not TLS or valid HTTP.
		// Treat as generic TCP and let the default handler deal with it.
		p.handleDefaultTCPConnection(prefixedConn)
		return
	}

	// Priority 1: Handle TLS traffic
	if peeked[0] == 0x16 {
		p.handleTLSConnection(prefixedConn)
		return
	}

	// Priority 2: Handle HTTP traffic
	// We need to peek more to identify HTTP methods
	peeked, err = prefixedConn.r.Peek(8)
	if err != nil {
		// Not enough data for an HTTP request, treat as generic TCP
		p.handleDefaultTCPConnection(prefixedConn)
		return
	}
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	isHTTP := false
	for _, method := range httpMethods {
		if strings.HasPrefix(string(peeked), method) {
			isHTTP = true
			break
		}
	}

	if isHTTP {
		p.handleHTTPConnection(prefixedConn)
		return
	}

	// Priority 3 (Fallback): Handle as generic TCP traffic
	p.handleDefaultTCPConnection(prefixedConn)
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

	// The connection is already a prefixedConn, so its reader has the peeked data.
	buffReader := clientConn.(*prefixedConn).r

	sniHost, err := extractSNI(buffReader)
	if err != nil {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to extract SNI")
		// As a fallback, treat as generic TCP. The default handler will take over.
		p.handleDefaultTCPConnection(clientConn)
		return
	}

	if sniHost == "" {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("SNI hostname not found, falling back to default TCP handler")
		p.handleDefaultTCPConnection(clientConn)
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":  clientConn.RemoteAddr(),
		"sni_hostname": sniHost,
		"proxy_type":   "SNI",
	}).Info("Extracted SNI hostname")

	bridgeAddr, ok := p.Manager.LoadBridgeAddress(sniHost)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": sniHost}).Error("Bridge for domain not found")
		return
	}

	backendConn, err := net.Dial("tcp", bridgeAddr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"domain":      sniHost,
			"bridge_addr": bridgeAddr,
		}).WithError(err).Error("Failed to connect to internal bridge for SNI proxy")
		return
	}

	// We don't need to re-wrap the connection here because the clientConn still holds
	// the buffered data that was peeked. When proxyData copies from it, the buffered
	// data will be read first, followed by the rest of the stream.
	proxyData(clientConn, backendConn)
}

// extractSNI manually parses the TLS ClientHello to get the server name, without
// completing the handshake. This is more efficient than the previous method.
func extractSNI(reader *bufio.Reader) (string, error) {
	// Peek at the TLS record header
	header, err := reader.Peek(5)
	if err != nil {
		return "", fmt.Errorf("failed to peek TLS record header: %w", err)
	}

	// Check if it's a TLS handshake record
	if header[0] != 0x16 { // 0x16 = Handshake
		return "", fmt.Errorf("not a TLS handshake record")
	}

	// The total length of the record is in bytes 3 and 4.
	recordLen := int(header[3])<<8 | int(header[4])
	if reader.Buffered() < recordLen+5 {
		// The full record is not yet in the buffer. This can happen with fragmented
		// ClientHello messages. For simplicity, we'll fail here. A more robust
		// implementation might wait for more data.
		return "", fmt.Errorf("fragmented ClientHello not supported")
	}

	// Peek the entire record
	record, err := reader.Peek(recordLen + 5)
	if err != nil {
		return "", fmt.Errorf("failed to peek full TLS record: %w", err)
	}

	// We're looking for the Server Name Indication (SNI) extension.
	// The structure is roughly:
	// - Record Header (5 bytes)
	// - Handshake Header (4 bytes)
	// - Client Version (2 bytes)
	// - Client Random (32 bytes)
	// - Session ID Length (1 byte) + Session ID
	// - Cipher Suites Length (2 bytes) + Cipher Suites
	// - Compression Methods Length (1 byte) + Compression Methods
	// - Extensions Length (2 bytes) + Extensions
	// We need to parse this to find the extensions block.

	// A full TLS parser is complex. We'll use a simplified approach to find the SNI.
	// We'll look for the SNI extension type (0x0000) in the extensions part.
	// This is not foolproof but works for most standard ClientHello messages.

	// Let's find the extensions block. We skip the static parts.
	offset := 5 + 4 + 2 + 32 // Record header, handshake header, version, random

	// Skip Session ID
	sessionIDLen := int(record[offset])
	offset += 1 + sessionIDLen

	// Skip Cipher Suites
	cipherSuitesLen := int(record[offset])<<8 | int(record[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip Compression Methods
	compressionMethodsLen := int(record[offset])
	offset += 1 + compressionMethodsLen

	// Now we should be at the extensions
	if offset+2 > len(record) {
		return "", fmt.Errorf("no extensions found in ClientHello")
	}

	extensionsLen := int(record[offset])<<8 | int(record[offset+1])
	offset += 2
	extensionsEnd := offset + extensionsLen

	if extensionsEnd > len(record) {
		return "", fmt.Errorf("invalid extensions length")
	}

	// Iterate through extensions
	for offset < extensionsEnd {
		if offset+4 > extensionsEnd {
			break
		}
		extType := int(record[offset])<<8 | int(record[offset+1])
		extLen := int(record[offset+2])<<8 | int(record[offset+3])
		offset += 4

		if extType == 0x0000 { // SNI Extension
			// We found it. Now parse the SNI data.
			if offset+extLen > extensionsEnd {
				return "", fmt.Errorf("invalid SNI extension length")
			}
			sniBlock := record[offset : offset+extLen]

			// SNI block contains a list of names.
			// First 2 bytes are the list length.
			if len(sniBlock) < 2 {
				return "", fmt.Errorf("invalid SNI block")
			}
			listLen := int(sniBlock[0])<<8 | int(sniBlock[1])
			if listLen+2 != len(sniBlock) {
				return "", fmt.Errorf("SNI list length mismatch")
			}

			// Move to the first name entry
			sniBlock = sniBlock[2:]
			for len(sniBlock) > 0 {
				// Name type (1 byte) and name length (2 bytes)
				if len(sniBlock) < 3 {
					return "", fmt.Errorf("incomplete SNI name entry")
				}
				nameType := sniBlock[0]
				nameLen := int(sniBlock[1])<<8 | int(sniBlock[2])
				sniBlock = sniBlock[3:]

				if nameType == 0x00 { // Hostname
					if len(sniBlock) < nameLen {
						return "", fmt.Errorf("hostname length mismatch in SNI")
					}
					return string(sniBlock[:nameLen]), nil
				}

				// Move to the next name
				sniBlock = sniBlock[nameLen:]
			}
		}

		offset += extLen
	}

	return "", fmt.Errorf("SNI extension not found")
}

// handleHTTPConnection handles plain HTTP traffic by proxying.
func (p *SNIProxy) handleHTTPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// The clientConn is already a prefixedConn, so its reader has the peeked data.
	buffReader := clientConn.(*prefixedConn).r
	req, err := http.ReadRequest(buffReader)
	if err != nil {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to read HTTP request")
		// Fallback to default TCP handler if reading fails
		p.handleDefaultTCPConnection(clientConn)
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
		"proxy_type":  "HTTP",
	}).Info("Identified HTTP request")

	bridgeAddr, ok := p.Manager.LoadBridgeAddress(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Bridge for domain not found during HTTP routing")
		// Optional: could write a 404 response to the client here
		return
	}

	backendConn, err := net.Dial("tcp", bridgeAddr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"domain":      domain,
			"bridge_addr": bridgeAddr,
		}).WithError(err).Error("Failed to connect to internal bridge for HTTP proxy")
		return
	}

	// We need to forward the entire request, including the body, to the bridge.
	err = req.Write(backendConn)
	if err != nil {
		logrus.WithFields(logrus.Fields{"domain": domain}).WithError(err).Error("Failed to write HTTP request to bridge")
		return
	}

	// After writing the request, proxy the rest of the data (e.g., response from server)
	// between the client and the bridge.
	proxyData(clientConn, backendConn)
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
