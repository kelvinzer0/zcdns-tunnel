package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"zcdns-tunnel/internal/tunnel"
)

// NewHTTPProxy creates a new HTTP reverse proxy that forwards requests to dynamically allocated ports.
func NewHTTPProxy(manager *tunnel.Manager) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			host := req.Host
			logrus.WithFields(logrus.Fields{
				"host":   host,
				"path":   req.URL.Path,
				"method": req.Method,
			}).Info("HTTP Proxy: Received request")

			// Find the dynamically allocated port for this domain
			port, ok := manager.LoadDomainForwardedPort(host)
			if !ok {
				logrus.WithFields(logrus.Fields{
					"host": host,
				}).Warn("HTTP Proxy: No dynamically allocated port found for host")
				// Set a dummy URL to prevent the proxy from trying to connect directly
				req.URL.Scheme = "http"
				req.URL.Host = "invalid.host"
				return
			}

			// The target URL for the proxy is the dynamically allocated port on localhost
			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", port)
			req.Host = host // Preserve the original host header

			logrus.WithFields(logrus.Fields{
				"original_host": host,
				"proxied_to":    req.URL.Host,
			}).Info("HTTP Proxy: Directing request")
		},
		// Use default transport, as the connection is now to a local port
		Transport: http.DefaultTransport,
	}
	return proxy
}
