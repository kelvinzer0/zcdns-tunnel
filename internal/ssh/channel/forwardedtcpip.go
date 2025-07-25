package channel

import (
	"io"
	"sync"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	interNodeSSH "zcdns-tunnel/internal/ssh"
)

// HandleForwardedTCPIP handles the "forwarded-tcpip" SSH channel type.
// This function is called on the *intermediate* node when the responsible node
// opens a forwarded channel back to it.
func HandleForwardedTCPIP(sshConn *gossh.ServerConn, newChannel gossh.NewChannel, forwardedClientConns map[string]*gossh.ServerConn, mu *sync.Mutex) {
	// The extra data for a forwarded-tcpip channel from another zcdns-tunnel node
	// will contain our custom InterNodeForwardedChannelPayload.
	var req interNodeSSH.InterNodeForwardedChannelPayload
	if err := gossh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to unmarshal inter-node forwarded-tcpip request")
		newChannel.Reject(gossh.Prohibited, "invalid payload")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":     sshConn.RemoteAddr(),
		"dest_addr":       req.DestAddr,
		"dest_port":       req.DestPort,
		"originator_ip":   req.OriginatorIP,
		"originator_port": req.OriginatorPort,
		"forward_id":      req.ForwardID,
	}).Info("Received inter-node forwarded-tcpip request")

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Could not accept inter-node forwarded-tcpip channel")
		return
	}
	defer channel.Close()

	go gossh.DiscardRequests(requests)

	// Retrieve the original client's SSH connection using the ForwardID
	mu.Lock()
	originalClientConn, ok := forwardedClientConns[req.ForwardID]
	if !ok {
		mu.Unlock()
		logrus.WithFields(logrus.Fields{
			"forward_id": req.ForwardID,
		}).Error("Original client connection not found for forwarded channel.")
		newChannel.Reject(gossh.UnknownChannelType, "original client connection not found")
		return
	}
	delete(forwardedClientConns, req.ForwardID) // Clean up the map entry
	mu.Unlock()

	// Open a new direct-tcpip channel back to the original client
	// The payload for direct-tcpip is: address to connect, port to connect, originator address, originator port
	directChannel, directRequests, err := originalClientConn.OpenChannel(
		"direct-tcpip",
		gossh.Marshal(
			struct {
				DestAddr       string
				DestPort       uint32
				OriginatorIP   string
				OriginatorPort uint32
			}{
				DestAddr:       req.DestAddr,
				DestPort:       req.DestPort,
				OriginatorIP:   req.OriginatorIP,
				OriginatorPort: req.OriginatorPort,
			},
		),
	)
	if err != nil {
		logrus.WithError(err).WithField("forward_id", req.ForwardID).Error("Failed to open direct-tcpip channel to original client.")
		return
	}
	defer directChannel.Close()
	go gossh.DiscardRequests(directRequests)

	logrus.WithFields(logrus.Fields{
		"forward_id": req.ForwardID,
		"client":     originalClientConn.RemoteAddr(),
		"remote":     sshConn.RemoteAddr(),
	}).Info("Proxying data between forwarded channel and original client.")

	// Proxy data between the two channels
	done := make(chan struct{})
	go func() {
		io.Copy(channel, directChannel)
		close(done)
	}()
	go func() {
		io.Copy(directChannel, channel)
		close(done)
	}()
	<-done
	<-done // Wait for both copy operations to finish

	logrus.WithFields(logrus.Fields{
		"forward_id": req.ForwardID,
	}).Info("Inter-node forwarded-tcpip channel proxying finished.")
}