package channel

import (
	"io"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// HandleForwardedTCPIP handles the "forwarded-tcpip" SSH channel type.
func HandleForwardedTCPIP(sshConn *gossh.ServerConn, newChannel gossh.NewChannel) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Error("No domain found in SSH connection permissions")
		newChannel.Reject(gossh.Prohibited, "internal server error")
		return
	}

	var req struct {
		ConnectedAddr  string
		ConnectedPort  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}
	if err := gossh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to unmarshal forwarded-tcpip request")
		newChannel.Reject(gossh.Prohibited, "invalid payload")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":     sshConn.RemoteAddr(),
		"domain":          domain,
		"connected_addr":  req.ConnectedAddr,
		"connected_port":  req.ConnectedPort,
		"originator_ip":   req.OriginatorIP,
		"originator_port": req.OriginatorPort,
	}).Info("Received forwarded-tcpip request")

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Could not accept forwarded-tcpip channel")
		return
	}
	defer channel.Close()

	go gossh.DiscardRequests(requests)

	// The client is expected to connect to its local service and proxy traffic.
	// We just need to keep the channel open and let the client handle the proxying.
	// This goroutine will block until the channel is closed.
	_, err = io.Copy(io.Discard, channel)
	if err != nil && err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			"domain":        domain,
			logrus.ErrorKey: err,
		}).Error("Error reading from forwarded-tcpip channel.")
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"domain":      domain,
	}).Info("Forwarded-tcpip channel closed.")
}
