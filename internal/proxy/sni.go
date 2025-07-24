package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"zcdns-tunnel/internal/tunnel"
	"zcdns-tunnel/internal/utils"

	"github.com/sirupsen/logrus"
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

	// Priority 2: Attempt to parse as HTTP
	// http.ReadRequest will consume from prefixedConn.r
	req, err := http.ReadRequest(prefixedConn.r)
	if err == nil {
		// Successfully parsed as HTTP
		p.handleHTTPConnection(prefixedConn, req)
		return
	} else if err != io.EOF {
		// Log error if it's not just EOF (e.g., malformed HTTP)
		logrus.WithField("remote_addr", prefixedConn.RemoteAddr()).WithError(err).Debug("Failed to parse as HTTP, falling back to TCP.")
	}

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
			"remote_addr":   clientConn.RemoteAddr(),
			"backend_addr":  backendAddr,
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
// handleTLSConnection handles TLS traffic by extracting the SNI and proxying.
func (p *SNIProxy) handleTLSConnection(clientConn net.Conn) {
	defer clientConn.Close()

	prefixed := clientConn.(*prefixedConn)
	reader := prefixed.r

	// Read the entire ClientHello message into a buffer.
	// We need to peek enough to get the full ClientHello, which can be variable length.
	// A typical ClientHello is usually less than 1KB, but can be larger.
	// We'll peek a reasonable amount, then read the full record.

	// Peek at the TLS record header (5 bytes)
	header, err := reader.Peek(5)
	if err != nil {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to peek TLS record header")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	// Check if it's a TLS handshake record (0x16)
	if header[0] != 0x16 {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Not a TLS handshake record, falling back to default TCP handler")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	// Get the total length of the TLS record from bytes 3 and 4 of the header.
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))

	// Read the entire TLS record (header + recordLen bytes)
	fullRecord := make([]byte, 5+recordLen)
	_, err = io.ReadFull(reader, fullRecord)
	if err != nil {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).WithError(err).Warn("Failed to read full TLS record")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	// Now, parse the ClientHello from the fullRecord to extract SNI.
	// The ClientHello message starts after the 5-byte TLS record header.
	clientHelloData := fullRecord[5:]

	// ClientHello Handshake Header (4 bytes): Type (0x01), Length (3 bytes)
	if len(clientHelloData) < 4 || clientHelloData[0] != 0x01 {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Not a valid ClientHello message, falling back to default TCP handler")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	// Skip ClientHello header (4 bytes)
	offset := 4

	// Skip Client Version (2 bytes)
	offset += 2

	// Skip Random (32 bytes)
	offset += 32

	// Skip Session ID (1 byte length + Session ID)
	if offset+1 > len(clientHelloData) {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed ClientHello: missing Session ID length")
		p.handleDefaultTCPConnection(prefixed)
		return
	}
	sessionIDLen := int(clientHelloData[offset])
	offset += 1 + sessionIDLen

	// Skip Cipher Suites (2 bytes length + Cipher Suites)
	if offset+2 > len(clientHelloData) {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed ClientHello: missing Cipher Suites length")
		p.handleDefaultTCPConnection(prefixed)
		return
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHelloData[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Skip Compression Methods (1 byte length + Compression Methods)
	if offset+1 > len(clientHelloData) {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed ClientHello: missing Compression Methods length")
		p.handleDefaultTCPConnection(prefixed)
		return
	}
	compressionMethodsLen := int(clientHelloData[offset])
	offset += 1 + compressionMethodsLen

	// Now we should be at the Extensions section.
	if offset+2 > len(clientHelloData) {
		// No extensions or malformed extensions length
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("No TLS extensions found or malformed length, falling back to default TCP handler")
		p.handleDefaultTCPConnection(prefixed)
		return
	}
	extensionsLen := int(binary.BigEndian.Uint16(clientHelloData[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	if extensionsEnd > len(clientHelloData) {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed TLS extensions length, falling back to default TCP handler")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	sniHost := ""
	// Iterate through extensions to find SNI (type 0x0000)
	for offset < extensionsEnd {
		if offset+4 > extensionsEnd {
			logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed TLS extension entry, stopping parsing")
			break
		}
		extType := binary.BigEndian.Uint16(clientHelloData[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(clientHelloData[offset+2 : offset+4]))
		offset += 4

		if extType == 0x0000 { // SNI Extension
			if offset+extLen > extensionsEnd {
				logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed SNI extension length")
				break
			}
			sniData := clientHelloData[offset : offset+extLen]

			// SNI data format: list length (2 bytes) + list of SNI entries
			if len(sniData) < 2 {
				logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed SNI data: missing list length")
				break
			}
			// sniListLen := binary.BigEndian.Uint16(sniData[0:2]) // Not strictly needed if we iterate
			sniData = sniData[2:] // Skip list length

			for len(sniData) > 0 {
				if len(sniData) < 3 {
					logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed SNI entry: too short")
					break
				}
				nameType := sniData[0] // 0x00 for hostname
				nameLen := int(binary.BigEndian.Uint16(sniData[1:3]))
				sniData = sniData[3:]

				if nameType == 0x00 { // Hostname
					if len(sniData) < nameLen {
						logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("Malformed SNI hostname: length mismatch")
						break
					}
					sniHost = string(sniData[:nameLen])
					break // Found SNI, no need to parse further
				}
				sniData = sniData[nameLen:] // Skip to next SNI entry
			}
		}
		offset += extLen // Move to next extension
	}

	// Prepend the full ClientHello record back to the connection.
	prefixed.Prepend(fullRecord)

	if sniHost == "" {
		logrus.WithField("remote_addr", clientConn.RemoteAddr()).Warn("SNI hostname not found in TLS handshake, falling back to default TCP handler")
		p.handleDefaultTCPConnection(prefixed)
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":  clientConn.RemoteAddr(),
		"sni_hostname": sniHost,
		"proxy_type":   "SNI",
	}).Info("Extracted SNI hostname")

	publicPort, err := strconv.ParseUint(strings.Split(p.ListenAddr, ":")[1], 10, 32)
	if err != nil {
		logrus.WithField("listen_addr", p.ListenAddr).WithError(err).Error("Failed to parse listen address port")
		return
	}

	protocolPrefix := "tls"

	bridgeAddr, ok := p.Manager.LoadBridgeAddress(sniHost, protocolPrefix, uint32(publicPort))
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

	proxyData(prefixed, backendConn)
}

// handleHTTPConnection handles plain HTTP traffic by proxying.
func (p *SNIProxy) handleHTTPConnection(clientConn net.Conn, req *http.Request) {
	defer clientConn.Close()

	

	domain := req.Host
	var publicPort uint32 = 80 // default HTTP port

	if strings.Contains(domain, ":") {
		parts := strings.Split(domain, ":")
		domain = parts[0]

		// Parse port from req.Host
		if len(parts) > 1 {
			port, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				logrus.WithField("req_host", req.Host).WithError(err).Error("Failed to parse port from request host")
				return
			}
			publicPort = uint32(port)
		}
	}

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"port":        publicPort,
		"source_ip":   clientConn.RemoteAddr(),
		"request_uri": req.RequestURI,
		"proxy_type":  "HTTP",
	}).Info("Identified HTTP request")

	protocolPrefix := "http"

	bridgeAddr, ok := p.Manager.LoadBridgeAddress(domain, protocolPrefix, publicPort)
	if !ok {
		logrus.WithFields(logrus.Fields{
			"domain": domain,
			"port":   publicPort,
		}).Error("Bridge for domain not found during HTTP routing")
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

	// After writing the request, including the body, to the bridge.
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

// Prepend prepends data to the buffered reader, making it available for subsequent reads.
func (c *prefixedConn) Prepend(data []byte) {
	c.r = bufio.NewReader(io.MultiReader(bytes.NewReader(data), c.r))
}

func (c *prefixedConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}
