package channel

import (
	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"
)

// HandleSession handles the "session" SSH channel type.
func HandleSession(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Warn("Received session channel. Rejecting.")
	newChannel.Reject(ssh.Prohibited, "session channels not allowed")
}