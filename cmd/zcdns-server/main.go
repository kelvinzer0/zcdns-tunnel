package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/server"
	"zcdns-tunnel/internal/gossip"
)

func main() {
	// Configure Logrus
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// Command line flag for the config file path
	configPath := flag.String("config", "configs/server.example.yml", "path to the server config file")
	// Add flags for gossip
	gossipAddr := flag.String("gossip-addr", "0.0.0.0:7946", "Local address for gossip communication (UDP)")
	seedPeers := flag.String("seed-peers", "", "Comma-separated list of seed peer addresses (IP:Port) for gossip")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize and start Gossip Service
	gossipService := gossip.NewGossipService(*gossipAddr)
	if err := gossipService.Start(); err != nil {
		logrus.Fatalf("Failed to start gossip service: %v", err)
	}
	defer gossipService.Stop()

	// If there are seed peers, try to join the cluster
	if *seedPeers != "" {
		peers := splitAndTrim(*seedPeers)
		gossipService.Join(peers)
	}

	// Create a context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create and start the SSH server
	sshServer := server.NewSSHServer(cfg, gossipService, *gossipAddr)
	go func() {
		if err := sshServer.StartSSHServer(ctx); err != nil {
			logrus.Printf("SSH server exited with error: %v", err)
		}
	}()

	// Listen for OS signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c // Block until a signal is received.

	logrus.Println("Shutting down gracefully...")
	cancel() // Tell goroutines to stop

	logrus.Println("Server exited.")
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}
