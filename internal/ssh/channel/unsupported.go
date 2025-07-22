package channel

import (
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// HandleUnsupportedChannel handles unsupported SSH channel types.
func HandleUnsupportedChannel(sshConn *gossh.ServerConn, newChannel gossh.NewChannel) {
	switch newChannel.ChannelType() {
	case "x11":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received X11 channel. Rejecting.")
		newChannel.Reject(gossh.Prohibited, "X11 channels not allowed")
		return
	case "auth-agent@openssh.com":
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Warn("Received auth-agent channel. Rejecting.")
		newChannel.Reject(gossh.Prohibited, "auth-agent channels not allowed")
		return
	default:
		logrus.WithFields(logrus.Fields{
			"remote_addr":  sshConn.RemoteAddr(),
			"channel_type": newChannel.ChannelType(),
		}).Warn("Unknown channel type. Rejecting.")
		newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
		return
	}
}
