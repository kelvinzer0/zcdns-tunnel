package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/tunnel"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	sshConnContextKey contextKey = "sshConn"
)

// sshChannelConn is a net.Conn wrapper around gossh.Channel.
type sshChannelConn struct {
	gossh.Channel
}

func (c *sshChannelConn) LocalAddr() net.Addr {
	return nil // Not applicable for SSH channels in this context
}

func (c *sshChannelConn) RemoteAddr() net.Addr {
	return nil // Not applicable for SSH channels in this context
}

func (c *sshChannelConn) SetDeadline(t time.Time) error {
	return nil // Not implemented for SSH channels
}

func (c *sshChannelConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for SSH channels
}

func (c *sshChannelConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for SSH channels
}

// SSHProxyTransport implements http.RoundTripper to proxy HTTP requests over an SSH channel.
type SSHProxyTransport struct {
	Manager *tunnel.Manager
}

// RoundTrip handles the HTTP request by opening a direct-tcpip SSH channel.
func (t *SSHProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Retrieve the SSH connection from the request context
	sshConn, ok := req.Context().Value(sshConnContextKey).(*gossh.ServerConn)
	if !ok || sshConn == nil {
		return nil, fmt.Errorf("SSH connection not found in request context")
	}

	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		return nil, fmt.Errorf("domain not found in SSH connection permissions")
	}

	// Determine the target address from the request URL
	targetHost := req.URL.Hostname()
	targetPort := req.URL.Port()
	if targetPort == "" {
		// Default to 80 for HTTP, 443 for HTTPS (though this proxy only handles HTTP)
		targetPort = "80"
	}

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"target_host": targetHost,
		"target_port": targetPort,
		"method":      req.Method,
		"path":        req.URL.Path,
	}).Info("HTTP Proxy: Opening direct-tcpip channel")

	// Open a direct-tcpip channel to the client's local service
	channel, requests, err := sshConn.OpenChannel("direct-tcpip", gossh.Marshal(&struct {
		HostToConnect  string
		PortToConnect  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		HostToConnect:  targetHost,
		PortToConnect:  uint32(atoi(targetPort)),
		OriginatorIP:   "127.0.0.1", // The proxy server's IP
		OriginatorPort: 0,           // Not relevant for the client
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to open direct-tcpip channel: %w", err)
	}
	defer channel.Close()

	go gossh.DiscardRequests(requests)

	// Create a new HTTP client to send the request over the SSH channel
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// This DialContext is for the internal client, it should just return the SSH channel
				// We need to wrap the ssh.Channel to implement net.Conn fully.
				return &sshChannelConn{
					Channel:    channel,
				}, nil
			},
		},
		// Do not follow redirects, as the SSH channel is a direct pipe
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Modify the request to be sent over the SSH channel
	// The URL scheme and host should be set to dummy values as the actual connection
	// is handled by the SSH channel.
	originalURL := req.URL.String()
	req.URL.Scheme = "http"
	req.URL.Host = "localhost"

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request over SSH channel: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"target_host": targetHost,
		"target_port": targetPort,
		"status":      resp.Status,
		"original_url": originalURL,
	}).Info("HTTP Proxy: Request proxied successfully")

	return resp, nil
}

// NewHTTPProxy creates a new HTTP reverse proxy that forwards requests over SSH.
func NewHTTPProxy(manager *tunnel.Manager) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			host := req.Host
			logrus.WithFields(logrus.Fields{
				"host":   host,
				"path":   req.URL.Path,
				"method": req.Method,
			}).Info("HTTP Proxy: Received request")

			// Find the active SSH client for this domain
			sshConn, ok := manager.LoadClient(host)
			if !ok {
				logrus.WithFields(logrus.Fields{
					"host": host,
				}).Warn("HTTP Proxy: No active client for host")
				// Set a dummy URL to prevent the proxy from trying to connect directly
				req.URL.Scheme = "http"
				req.URL.Host = "invalid.host"
				return
			}

			// Store the SSH connection in the request context for the Transport to use
			ctx := context.WithValue(req.Context(), sshConnContextKey, sshConn)
			*req = *req.WithContext(ctx)

			// The actual target will be determined by the SSHProxyTransport
			// We just need to ensure the scheme and host are set for the Director's internal logic
			req.URL.Scheme = "http"
			req.URL.Host = host // Keep the original host for the Transport to extract
			req.Host = host    // Preserve the original host header
		},
		Transport: &SSHProxyTransport{Manager: manager},
	}
	return proxy
}

// atoi is a simple Atoi implementation for uint32.
func atoi(s string) uint32 {
	var i uint32
	fmt.Sscanf(s, "%d", &i)
	return i
}