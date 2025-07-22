package server

import (
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	_ "zcdns-tunnel/internal/tunnel"
)

// handleGlobalRequests handles global SSH requests like tcpip-forward and cancel-tcpip-forward.
func (s *SSHServer) handleGlobalRequests(sshConn *gossh.ServerConn, reqs <-chan *gossh.Request) {
	domain, ok := sshConn.Permissions.Extensions["domain"]
	if !ok || domain == "" {
		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
		}).Error("No domain found in SSH connection permissions for global request")
		return
	}

	for req := range reqs {
		var err error // Declare err once at the beginning of the loop
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err = gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			requestedAddr := net.JoinHostPort(payload.BindAddr, fmt.Sprintf("%d", payload.BindPort))
			logrus.WithFields(logrus.Fields{
				"remote_addr":    sshConn.RemoteAddr(),
				"bind_addr":      payload.BindAddr,
				"bind_port":      payload.BindPort,
				"requested_addr": requestedAddr,
			}).Info("Received tcpip-forward request")

			var listener net.Listener
			var actualPort uint32

			// Try to listen on the requested address first
			listener, err = net.Listen("tcp", requestedAddr)
			if err != nil {
				// If the requested address is already in use, try to bind to a random available port
				if opErr, ok := err.(*net.OpError); ok && opErr.Err != nil && opErr.Err == syscall.EADDRINUSE {
					logrus.WithFields(logrus.Fields{
						"remote_addr":    sshConn.RemoteAddr(),
						"bind_addr_port": requestedAddr,
						logrus.ErrorKey:  err,
					}).Warn("Requested port already in use, trying dynamic allocation.")

					listener, err = net.Listen("tcp", net.JoinHostPort(payload.BindAddr, "0"))
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"remote_addr":    sshConn.RemoteAddr(),
							"bind_addr_port": requestedAddr,
							logrus.ErrorKey:  err,
						}).Error("Failed to listen for remote forwarding on random port")
						req.Reply(false, nil)
						continue
					}
					actualPort = uint32(listener.Addr().(*net.TCPAddr).Port)
					logrus.WithFields(logrus.Fields{
						"remote_addr":    sshConn.RemoteAddr(),
						"requested_port": payload.BindPort,
						"actual_port":    actualPort,
					}).Info("Dynamically allocated port for remote forwarding")
					s.Manager.StoreDomainForwardedPort(domain, actualPort)
				} else {
					logrus.WithFields(logrus.Fields{
						"remote_addr":    sshConn.RemoteAddr(),
						"bind_addr_port": requestedAddr,
						logrus.ErrorKey:  err,
					}).Error("Failed to listen for remote forwarding")
					req.Reply(false, nil)
					continue
				}
			} else {
				actualPort = uint32(listener.Addr().(*net.TCPAddr).Port)
			}

			if err = s.Manager.StoreRemoteListener(listener.Addr().String(), listener, sshConn); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":    sshConn.RemoteAddr(),
					"bind_addr_port": listener.Addr().String(),
					logrus.ErrorKey:  err,
				}).Warn("Port already in use for remote forwarding.")
				listener.Close() // Close the listener if storing fails
				req.Reply(false, nil)
				continue
			}

			// Reply to the client with the actual bound port
			req.Reply(true, gossh.Marshal(&struct{ Port uint32 }{Port: actualPort}))
			logrus.WithFields(logrus.Fields{
				"remote_addr":    sshConn.RemoteAddr(),
				"bind_addr_port": listener.Addr().String(),
				"actual_port":    actualPort,
				"domain_for_store_raw": fmt.Sprintf("%q", domain),
			}).Info("Successfully opened remote forwarded port.")

			// Start accepting connections on this new listener
			go s.handleRemoteForwardedConnections(sshConn, listener, payload.BindAddr, actualPort)

		case "cancel-tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err = gossh.Unmarshal(req.Payload, &payload); err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					logrus.ErrorKey: err,
				}).Error("Failed to unmarshal cancel-tcpip-forward request")
				req.Reply(false, nil)
				continue
			}

			addr := net.JoinHostPort(payload.BindAddr, fmt.Sprintf("%d", payload.BindPort))
			logrus.WithFields(logrus.Fields{
				"remote_addr":    sshConn.RemoteAddr(),
				"bind_addr_port": addr,
			}).Info("Received cancel-tcpip-forward request")

			if rfPort, loaded := s.Manager.LoadAndDeleteRemoteListener(addr); loaded {
				rfPort.Listener.Close()
				logrus.WithFields(logrus.Fields{
					"remote_addr":    sshConn.RemoteAddr(),
					"bind_addr_port": addr,
				}).Info("Successfully closed remote forwarded port.")
				req.Reply(true, nil)
			} else {
				logrus.WithFields(logrus.Fields{
					"remote_addr":    sshConn.RemoteAddr(),
					"bind_addr_port": addr,
				}).Warn("Remote forwarded port not found for cancellation.")
				req.Reply(false, nil)
			}

			// Remove the domain-to-port mapping as well
			s.Manager.DeleteDomainForwardedPort(domain)

		default:
			logrus.WithFields(logrus.Fields{
				"remote_addr":  sshConn.RemoteAddr(),
				"request_type": req.Type,
			}).Warn("Unknown global request type")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleRemoteForwardedConnections accepts connections on a remotely forwarded port
// and proxies them back to the SSH client.
func (s *SSHServer) handleRemoteForwardedConnections(sshConn *gossh.ServerConn, listener net.Listener, bindAddr string, bindPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed, or other error. Log and exit.
			logrus.WithFields(logrus.Fields{
				"remote_addr":   sshConn.RemoteAddr(),
				"bind_addr":     bindAddr,
				"bind_port":     bindPort,
				logrus.ErrorKey: err,
			}).Info("Remote forwarded listener stopped accepting connections.")
			return
		}

		logrus.WithFields(logrus.Fields{
			"remote_addr": sshConn.RemoteAddr(),
			"bind_addr":   bindAddr,
			"bind_port":   bindPort,
			"client_conn": conn.RemoteAddr(),
		}).Info("Accepted connection on remote forwarded port.")

		go func() {
			defer conn.Close()

			// Open a forwarded-tcpip channel back to the client
			channel, requests, err := sshConn.OpenChannel("forwarded-tcpip", gossh.Marshal(&struct {
				ConnectedAddr  string
				ConnectedPort  uint32
				OriginatorIP   string
				OriginatorPort uint32
			}{
				ConnectedAddr:  bindAddr,
				ConnectedPort:  bindPort,
				OriginatorIP:   conn.RemoteAddr().(*net.TCPAddr).IP.String(),
				OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
			}))
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"remote_addr":   sshConn.RemoteAddr(),
					"bind_addr":     bindAddr,
					"bind_port":     bindPort,
					logrus.ErrorKey: err,
				}).Error("Failed to open forwarded-tcpip channel.")
				return
			}
			defer channel.Close()

			go gossh.DiscardRequests(requests)

			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   bindAddr,
				"bind_port":   bindPort,
			}).Info("Proxying traffic for remote forwarded connection.")

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				io.Copy(channel, conn)
				channel.CloseWrite()
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, channel)
				// conn.CloseWrite() // Not needed as defer conn.Close() handles it
			}()

			wg.Wait()
			logrus.WithFields(logrus.Fields{
				"remote_addr": sshConn.RemoteAddr(),
				"bind_addr":   bindAddr,
				"bind_port":   bindPort,
			}).Info("Remote forwarded proxying finished.")
		}()
	}
}
