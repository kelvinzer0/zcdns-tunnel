package channel

import (
	"sync"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"zcdns-tunnel/internal/tunnel"
)

// HandleSession handles the "session" SSH channel type.
func HandleSession(sshConn *gossh.ServerConn, newChannel gossh.NewChannel, manager *tunnel.Manager) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"remote_addr":   sshConn.RemoteAddr(),
			logrus.ErrorKey: err,
		}).Error("Failed to accept session channel")
		return
	}

	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Error("No domain found in SSH connection permissions for session")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"domain":      domain,
	}).Info("Session channel accepted")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range requests {
			handleSessionRequest(req, domain, manager)
		}
	}()

	// When the client sends `ssh -N`, it opens a session but sends no requests.
	// The session stays open until the client disconnects. We can close our side.
	// For interactive sessions, this would be where you handle stdin/stdout.
	channel.Close()
	wg.Wait()

	logrus.WithFields(logrus.Fields{
		"remote_addr": sshConn.RemoteAddr(),
		"domain":      domain,
	}).Info("Session channel closed")
}

func handleSessionRequest(req *gossh.Request, domain string, manager *tunnel.Manager) {
	switch req.Type {
	case "env":
		var payload struct {
			Name  string
			Value string
		}
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			logrus.WithFields(logrus.Fields{
				"domain": domain,
			}).Warn("Failed to unmarshal env request")
			return
		}

		logrus.WithFields(logrus.Fields{
			"domain": domain,
			"name":   payload.Name,
			"value":  payload.Value,
		}).Info("Received env request")

		if payload.Name == "HTTP" && payload.Value == "TRUE" {
			manager.StoreHttpRequest(domain)
		}

	case "pty-req", "shell", "exec", "subsystem":
		// Reject these requests as we are only a tunnel server
		logrus.WithFields(logrus.Fields{
			"domain":      domain,
			"request_type": req.Type,
		}).Warn("Rejecting unsupported session request")
		if req.WantReply {
			req.Reply(false, nil)
		}

	default:
		logrus.WithFields(logrus.Fields{
			"domain":      domain,
			"request_type": req.Type,
		}).Warn("Unhandled session request type")
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}
