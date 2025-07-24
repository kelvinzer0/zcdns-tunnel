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
		logrus.WithFields(logrus.Fields{
			"remote_addr": conn.RemoteAddr(),
			"username":    conn.User(),
		}).Info("SSH: Auth attempt")

		// Parse the username to extract protocol prefix and domain
		usernameParts := strings.SplitN(conn.User(), ".", 2)
		var protocolPrefix, domain string
		if len(usernameParts) == 2 && (usernameParts[0] == "http" || usernameParts[0] == "tls") {
			protocolPrefix = usernameParts[0]
			domain = usernameParts[1]
		} else {
			// If no prefix, assume it's the domain itself and no specific protocol
			domain = conn.User()
			protocolPrefix = ""
		}

		if domain == "" {
			logrus.WithField("username", conn.User()).Warn("Auth: Invalid username format")
			return nil, fmt.Errorf("invalid username format")
		}

		// Perform domain validation using the extracted domain
		if err := a.validator.Validate(domain, conn.RemoteAddr(), key); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		// Store the domain and protocol prefix in permissions for later use
		return &gossh.Permissions{
			Extensions: map[string]string{
				"domain":         domain,
				"protocol_prefix": protocolPrefix,
			},
		}, nil
	}
}
