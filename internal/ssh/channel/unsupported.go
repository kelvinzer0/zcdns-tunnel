package channel

import (
	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"
)

// HandleUnsupportedChannel handles unsupported SSH channel types.
func HandleUnsupportedChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "x11":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received X11 channel. Rejecting.")
		newChannel.Reject(ssh.Prohibited, "X11 channels not allowed")
		return
	case "auth-agent@openssh.com":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received auth-agent channel. Rejecting.")
		newChannel.Reject(ssh.Prohibited, "auth-agent channels not allowed")
		return
	default:
		logrus.WithFields(logrus.Fields{
			"remote_addr":  sshConn.RemoteAddr(),
			"channel_type": newChannel.ChannelType(),
		}).Warn("Unknown channel type. Rejecting.")
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}
}
