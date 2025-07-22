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

// RemoteForwardedPort represents a port opened for remote forwarding on the server.
type RemoteForwardedPort struct {
	Listener net.Listener
	SshConn  *gossh.ServerConn
}