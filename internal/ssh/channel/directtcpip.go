package channel

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	ssh "golang.org/x/crypto/ssh"
)

// HandleDirectTCPIP handles the "direct-tcpip" SSH channel type.
func HandleDirectTCPIP(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Error("No domain found in SSH connection permissions")
		newChannel.Reject(ssh.Prohibited, "internal server error")
		return
	}

	var req struct {
		HostToConnect  string
		PortToConnect  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to unmarshal direct-tcpip request")
		newChannel.Reject(ssh.Prohibited, "invalid payload")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr":     sshConn.RemoteAddr(),
		"domain":          domain,
		"target_host":     req.HostToConnect,
		"target_port":     req.PortToConnect,
		"originator_ip":   req.OriginatorIP,
		"originator_port": req.OriginatorPort,
	}).Info("Received direct-tcpip request")

	// The backend address is now determined by the client's request.
	backendAddr := net.JoinHostPort(req.HostToConnect, fmt.Sprintf("%d", req.PortToConnect))

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			"domain":        domain,
			"backend_addr":  backendAddr,
			logrus.ErrorKey: err,
		}).Error("Failed to connect to backend")
		newChannel.Reject(ssh.ConnectionFailed, "failed to connect to backend")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Could not accept channel")
		backendConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	logrus.WithFields(logrus.Fields{
		"remote_addr":  sshConn.RemoteAddr(),
		"domain":       domain,
		"backend_addr": backendAddr,
	}).Info("Proxying traffic")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer channel.Close()
		defer backendConn.Close()
		io.Copy(channel, backendConn)
	}()
	go func() {
		defer wg.Done()
		defer channel.Close()
		defer backendConn.Close()
		io.Copy(backendConn, channel)
	}()

	wg.Wait()
	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"domain":      domain,
	}).Info("Proxying finished")
}
