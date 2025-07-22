package auth

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// SSHAuthenticator provides a PublicKeyCallback for SSH server authentication.
type SSHAuthenticator struct {
	validator *DomainValidator
}

// NewSSHAuthenticator creates a new SSHAuthenticator.
func NewSSHAuthenticator(validationDomain string) *SSHAuthenticator {
	return &SSHAuthenticator{
		validator: NewDomainValidator(validationDomain),
	}
}

// PublicKeyCallback returns a gossh.ServerConfig.PublicKeyCallback function
// that handles public key authentication with CNAME and TXT record validation
// using the embedded DomainValidator.
func (a *SSHAuthenticator) PublicKeyCallback() func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		fullUsername := conn.User()
		domain := fullUsername
		isHTTPProxy := false

		// Check for http. prefix for HTTP proxy tunnels
		if strings.HasPrefix(fullUsername, "http.") {
			domain = strings.TrimPrefix(fullUsername, "http.")
			isHTTPProxy = true
		}

		logrus.WithFields(logrus.Fields{
			"remote_addr": conn.RemoteAddr(),
			"username":    fullUsername,
			"domain":      domain,
			"is_http_proxy": isHTTPProxy,
		}).Info("SSH: Auth attempt")

		if err := a.validator.Validate(domain, conn.RemoteAddr(), key); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		permissions := &gossh.Permissions{
			Extensions: map[string]string{
				"domain": domain,
			},
		}

		if isHTTPProxy {
			permissions.Extensions["is_http_proxy"] = "true"
		}

		return permissions, nil
	}
}
