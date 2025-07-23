package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// Manager handles the lifecycle of active SSH client connections and their associated
// remote forwarded ports.
type Manager struct {
	// activeClients maps domain to the SSH server connection handling it
	activeClients sync.Map // map[string]*gossh.ServerConn

	// remoteListeners maps "bind_addr:bind_port" to RemoteForwardedPort
	remoteListeners sync.Map // map[string]*RemoteForwardedPort

	// domainForwardedPorts maps domain to the actual port bound for remote forwarding
	domainForwardedPorts sync.Map // map[string]uint32

	// domainBridgeAddrs maps domain to its domainPortBridges.
	domainBridgeAddrs sync.Map // map[string]*domainPortBridges
}

// domainPortBridges holds a map of public ports to their internal bridge addresses.
type domainPortBridges struct {
	mu      sync.RWMutex
	bridges map[uint32]string
}

// NewManager creates a new tunnel manager.
func NewManager() *Manager {
	return &Manager{}
}

// StoreClient stores an active SSH client connection.
func (m *Manager) StoreClient(domain string, conn *gossh.ServerConn) {
	m.activeClients.Store(domain, conn)
	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Stored active client for domain.")
}

// LoadClient loads an active SSH client connection by domain.
func (m *Manager) LoadClient(domain string) (*gossh.ServerConn, bool) {
	client, ok := m.activeClients.Load(domain)
	if !ok {
		return nil, false
	}
	sshConn, ok := client.(*gossh.ServerConn)
	return sshConn, ok
}

// DeleteClient deletes an active SSH client connection and cleans up associated remote listeners.
func (m *Manager) DeleteClient(domain string, sshConn *gossh.ServerConn) {
	m.activeClients.Delete(domain)
	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Removed active client for domain on SSH connection close.")

	// Clean up any remote forwarded listeners associated with this SSH connection
	m.remoteListeners.Range(func(key, value interface{}) bool {
		if rfPort, ok := value.(*RemoteForwardedPort); ok && rfPort.SshConn == sshConn {
			logrus.WithFields(logrus.Fields{
				"bind_addr_port": key,
			}).Info("Closing remote forwarded listener on SSH connection close.")
			rfPort.Listener.Close()
			m.remoteListeners.Delete(key)
		}
		return true
	})

	// Also remove the domain-to-port mapping
	m.domainForwardedPorts.Delete(domain)

	// And the domain-to-bridge mapping
	// We need to iterate and delete all bridges for this domain
	if v, ok := m.domainBridgeAddrs.Load(domain); ok {
		dpb := v.(*domainPortBridges)
		dpb.mu.Lock()
		for port := range dpb.bridges {
			delete(dpb.bridges, port)
		}
		dpb.mu.Unlock()
		m.domainBridgeAddrs.Delete(domain)
		logrus.WithField("domain", domain).Info("Removed all bridge addresses for domain on SSH connection close.")
	}
}

// StoreRemoteListener stores a remote forwarded port listener.
func (m *Manager) StoreRemoteListener(addr string, listener net.Listener, sshConn *gossh.ServerConn) error {
	// Check if port is already in use or reserved
	if _, loaded := m.remoteListeners.LoadOrStore(addr, nil); loaded {
		return fmt.Errorf("port %s already in use for remote forwarding", addr)
	}
	m.remoteListeners.Store(addr, &RemoteForwardedPort{Listener: listener, SshConn: sshConn})
	return nil
}

// LoadAndDeleteRemoteListener loads and deletes a remote forwarded port listener.
func (m *Manager) LoadAndDeleteRemoteListener(addr string) (*RemoteForwardedPort, bool) {
	if rfPort, loaded := m.remoteListeners.LoadAndDelete(addr); loaded {
		if p, ok := rfPort.(*RemoteForwardedPort); ok {
			return p, true
		}
	}
	return nil, false
}

// StoreUserBindingPort stores the actual bound port for a domain.
func (m *Manager) StoreUserBindingPort(domain string, port uint32) {
	m.domainForwardedPorts.Store(domain, port)
	logrus.WithFields(logrus.Fields{
		"domain_stored_raw": fmt.Sprintf("%q", domain),
		"port_stored":       port,
	}).Info("Manager: Storing user binding port.")

	// NEW LOG: Verify immediately after store
	if val, ok := m.domainForwardedPorts.Load(domain); ok {
		logrus.WithFields(logrus.Fields{
			"domain_verified_raw": fmt.Sprintf("%q", domain),
			"verified_value":      val,
		}).Info("Manager: Successfully verified stored user binding port immediately after store.")
	} else {
		logrus.WithFields(logrus.Fields{
			"domain_verified_raw": fmt.Sprintf("%q", domain),
		}).Error("Manager: Failed to verify stored user binding port immediately after store. THIS IS A CRITICAL ERROR.")
	}
}

// LoadUserBindingPort loads the actual bound port for a domain.
func (m *Manager) LoadUserBindingPort(domain string) (uint32, bool) {
	logrus.WithFields(logrus.Fields{"domain_looked_up_raw": fmt.Sprintf("%q", domain)}).Info("Manager: Loading user binding port.")
	val, ok := m.domainForwardedPorts.Load(domain)
	if !ok {
		logrus.WithFields(logrus.Fields{"domain_looked_up_raw": fmt.Sprintf("%q", domain)}).Warn("Manager: Domain not found in map during user binding port load.")
		return 0, false
	}
	if p, ok := val.(uint32); ok {
		return p, true
	}
	logrus.WithFields(logrus.Fields{"domain_looked_up_raw": fmt.Sprintf("%q", domain), "value_type": fmt.Sprintf("%T", val)}).Warn("Manager: Stored value for user binding port is not uint32.")
	return 0, false
}

// DeleteDomainForwardedPort deletes the domain-to-port mapping.
func (m *Manager) DeleteDomainForwardedPort(domain string) {
	m.domainForwardedPorts.Delete(domain)
	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Removed domain forwarded port.")
}

// StoreBridgeAddress stores the internal bridge address for a domain and public port.
func (m *Manager) StoreBridgeAddress(domain string, publicPort uint32, addr string) {
	v, _ := m.domainBridgeAddrs.LoadOrStore(domain, &domainPortBridges{bridges: make(map[uint32]string)})
	dpb := v.(*domainPortBridges)
	dpb.mu.Lock()
	defer dpb.mu.Unlock()
	dpb.bridges[publicPort] = addr
	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"public_port": publicPort,
		"bridge_addr": addr,
	}).Info("Stored bridge address for domain and port.")
}

// LoadBridgeAddress loads the internal bridge address for a domain and public port.
func (m *Manager) LoadBridgeAddress(domain string, publicPort uint32) (string, bool) {
	v, ok := m.domainBridgeAddrs.Load(domain)
	if !ok {
		return "", false
	}
	dpb := v.(*domainPortBridges)
	dpb.mu.RLock()
	defer dpb.mu.RUnlock()
	addr, ok := dpb.bridges[publicPort]
	return addr, ok
}

// DeleteBridgeAddress deletes the internal bridge address for a domain and public port.
func (m *Manager) DeleteBridgeAddress(domain string, publicPort uint32) {
	v, ok := m.domainBridgeAddrs.Load(domain)
	if !ok {
		return
	}
	dpb := v.(*domainPortBridges)
	dpb.mu.Lock()
	defer dpb.mu.Unlock()
	delete(dpb.bridges, publicPort)
	logrus.WithFields(logrus.Fields{
		"domain":      domain,
		"public_port": publicPort,
	}).Info("Removed bridge address for domain and port.")

	// If no more bridges for this domain, remove the domain entry itself
	if len(dpb.bridges) == 0 {
		m.domainBridgeAddrs.Delete(domain)
		logrus.WithField("domain", domain).Info("Removed all bridge addresses for domain.")
	}
}

// RemoteForwardedPort represents a port opened for remote forwarding on the server.
type RemoteForwardedPort struct {
	Listener net.Listener
	SshConn  *gossh.ServerConn
}
