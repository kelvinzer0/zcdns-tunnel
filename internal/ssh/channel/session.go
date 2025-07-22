package channel

import (
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// HandleSession handles the "session" SSH channel type.
func HandleSession(sshConn *gossh.ServerConn, newChannel gossh.NewChannel) {
	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
	}).Warn("Received session channel. Rejecting.")
	newChannel.Reject(gossh.Prohibited, "session channels not allowed")
}
