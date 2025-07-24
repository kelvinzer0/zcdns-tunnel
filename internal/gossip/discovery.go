package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// DiscoverPeerIPs uses DNS A record lookups to find the initial set of peer IPs for the gossip cluster.
func DiscoverPeerIPs(ctx context.Context, domain string) ([]net.IP, error) {
	// Use a custom resolver to ensure we're not using a cached response that might be stale.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			// We can use a public DNS resolver like Google's or Cloudflare's to avoid local DNS issues.
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve seed peers for domain %q: %w", domain, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records found for seed domain %q", domain)
	}

	var peerIPs []net.IP
	for _, ip := range ips {
		peerIPs = append(peerIPs, ip.IP)
	}

	return peerIPs, nil
}

// DiscoverPublicIP sends a WhoAmI message to a seed peer to learn its own public IP address.
func DiscoverPublicIP(ctx context.Context, seedPeers []string) (string, error) {
	if len(seedPeers) == 0 {
		return "", fmt.Errorf("cannot discover public IP without any seed peers")
	}

	// Bind to a local UDP port to send the message
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return "", fmt.Errorf("failed to resolve local UDP address: %w", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return "", fmt.Errorf("failed to listen on UDP port: %w", err)
	}
	defer conn.Close()

	msg := GossipMessage{Type: MessageTypeWhoAmI}
	msgBytes, _ := json.Marshal(msg)

	// Try each seed peer until we get a response
	for _, peerAddr := range seedPeers {
		logrus.Debugf("Attempting to discover public IP via seed peer: %s", peerAddr)
		targetAddr, err := net.ResolveUDPAddr("udp", peerAddr)
		if err != nil {
			logrus.Warnf("Failed to resolve seed peer address %s: %v", peerAddr, err)
			continue
		}

		// Send the WhoAmI message
		if _, err := conn.WriteTo(msgBytes, targetAddr); err != nil {
			logrus.Warnf("Failed to send WhoAmI message to %s: %v", peerAddr, err)
			continue
		}

		// Wait for a response
		conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 5-second timeout
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			logrus.Warnf("Did not receive WhoAmIResponse from %s: %v", peerAddr, err)
			continue // Try next peer
		}

		var respMsg GossipMessage
		if err := json.Unmarshal(buf[:n], &respMsg); err != nil {
			logrus.Warnf("Failed to unmarshal WhoAmIResponse: %v", err)
			continue
		}

		if respMsg.Type == MessageTypeWhoAmIResponse {
			var payload WhoAmIResponsePayload
			if err := json.Unmarshal(respMsg.Payload, &payload); err != nil {
				logrus.Warnf("Failed to unmarshal WhoAmIResponse payload: %v", err)
				continue
			}
			logrus.Infof("Discovered public address: %s", payload.PublicAddr)
			return payload.PublicAddr, nil
		}
	}

	return "", fmt.Errorf("failed to discover public IP from any seed peer")
}
