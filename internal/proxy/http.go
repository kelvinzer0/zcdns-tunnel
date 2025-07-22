package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"zcdns-tunnel/internal/tunnel"
)

// HTTPProxy handles routing HTTP requests to the correct SSH tunnel.
type HTTPProxy struct {
	manager *tunnel.Manager
}

// NewHTTPProxy creates a new HTTPProxy handler.
func NewHTTPProxy(manager *tunnel.Manager) http.Handler {
	return &HTTPProxy{manager: manager}
}

// ServeHTTP is the entry point for incoming HTTP requests.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract domain from the Host header
	domain := r.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	// Check if this domain has registered for HTTP proxying
	if !p.manager.IsHttpRequest(domain) {
		logrus.WithFields(logrus.Fields{"domain": domain}).Warn("Received request for non-HTTP domain")
		http.NotFound(w, r)
		return
	}

	// Find the dynamically allocated port for this domain's tunnel
	logrus.WithFields(logrus.Fields{"domain_to_lookup_raw": fmt.Sprintf("%q", domain)}).Info("Attempting to load user binding port")
	port, ok := p.manager.LoadUserBindingPort(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain": domain}).Error("Tunnel for domain is down or not found")
		http.Error(w, "Tunnel not available", http.StatusBadGateway)
		return
	}

	// Create the reverse proxy to the local port that is being forwarded to the client
	targetURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", port))
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	logrus.WithFields(logrus.Fields{
		"domain":        domain,
		"target_url":    targetURL.String(),
		"source_ip":     r.RemoteAddr,
		"request_uri":   r.RequestURI,
	}).Info("Forwarding HTTP request")

	proxy.ServeHTTP(w, r)
}
