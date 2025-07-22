package auth

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// DomainValidator performs CNAME and TXT record validation for SSH authentication.
type DomainValidator struct {
	ValidationDomain string
}

// NewDomainValidator creates a new DomainValidator.
func NewDomainValidator(validationDomain string) *DomainValidator {
	return &DomainValidator{
		ValidationDomain: validationDomain,
	}
}

// Validate performs CNAME and TXT record validation.
func (v *DomainValidator) Validate(domain string, remoteAddr net.Addr, publicKey gossh.PublicKey) error {
	logrus.WithFields(logrus.Fields{
		"remote_addr": remoteAddr,
		"domain":      domain,
	}).Info("Auth: Attempting domain validation")

	// CNAME validation
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   remoteAddr,
			"domain":        domain,
			logrus.ErrorKey: err,
		}).Warn("Auth: Failed to lookup CNAME for domain")
		return fmt.Errorf("failed to lookup CNAME")
	}

	// The CNAME must point to the validation domain.
	// The CNAME lookup often returns a final, non-alias record, so we check if the result
	// is the validation domain itself (with a trailing dot).
	if !strings.HasSuffix(cname, v.ValidationDomain+".") {
		logrus.WithFields(logrus.Fields{
			"remote_addr":     remoteAddr,
			"domain":          domain,
			"cname_found":     cname,
			"expected_domain": v.ValidationDomain,
		}).Warn("Auth: CNAME validation failed")
		return fmt.Errorf("CNAME validation failed")
	}

	// TXT record for public key
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   remoteAddr,
			"domain":        domain,
			logrus.ErrorKey: err,
		}).Warn("Auth: Failed to lookup TXT record for domain")
		return fmt.Errorf("failed to lookup TXT record")
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "zcdns-ssh-key=") {
			parts := strings.SplitN(record, "=", 2)
			if len(parts) == 2 {
				authKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(parts[1]))
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"remote_addr":   remoteAddr,
						"domain":        domain,
						logrus.ErrorKey: err,
					}).Warn("Auth: Failed to parse public key from TXT record")
					continue
				}
				if bytes.Equal(publicKey.Marshal(), authKey.Marshal()) {
					logrus.WithFields(logrus.Fields{
						"remote_addr": remoteAddr,
						"domain":      domain,
					}).Info("Auth: Public key authenticated successfully")
					return nil
				}
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": remoteAddr,
		"domain":      domain,
	}).Warn("Auth: Public key authentication failed")
	return fmt.Errorf("public key authentication failed")
}
