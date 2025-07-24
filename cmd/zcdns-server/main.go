package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/gossip"
	"zcdns-tunnel/internal/server"
)

func main() {
	// Configure Logrus
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel) // Change to logrus.DebugLevel for more verbose output

	// Command line flag for the config file path
	configPath := flag.String("config", "configs/server.yml", "path to the server config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Create a context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Gossip and Clustering Setup ---
	var gossipService *gossip.GossipService

	// 1. Discover seed peer IPs from DNS
	logrus.Info("Discovering seed peer IPs from DNS...")
	seedIPs, err := gossip.DiscoverPeerIPs(ctx, cfg.ValidationDomain)
	if err != nil {
		logrus.Fatalf("Could not discover seed peers, cannot start: %v", err)
	}

	var seedPeers []string
	for _, ip := range seedIPs {
		seedPeers = append(seedPeers, fmt.Sprintf("%s:%d", ip.String(), gossip.DefaultGossipPort))
	}

	// 2. Discover our own public IP using a seed peer
	logrus.Info("Discovering public IP...")
	publicAddr, err := gossip.DiscoverPublicIP(ctx, seedPeers)
	if err != nil {
		logrus.Fatalf("Could not discover public IP, cannot start: %v", err)
	}

	// 3. Initialize and start the Gossip Service
	logrus.Info("Initializing gossip service...")
	gossipService, err = gossip.NewGossipService(cfg.Gossip, cfg.ValidationDomain, publicAddr)
	if err != nil {
		logrus.Fatalf("Failed to create gossip service: %v", err)
	}

	if err := gossipService.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start gossip service: %v", err)
	}
	defer gossipService.Stop()

	// --- SSH Server Setup ---
	// Create and start the SSH server
	sshServer := server.NewSSHServer(cfg, gossipService, publicAddr)
	go func() {
		if err := sshServer.StartSSHServer(ctx); err != nil {
			logrus.Printf("SSH server exited with error: %v", err)
		}
	}()

	// Listen for OS signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	<-c

	logrus.Println("Shutting down gracefully...")
	// The deferred cancel() will handle context cancellation

	// Add a small delay to allow services to shut down
	time.Sleep(1 * time.Second)

	logrus.Println("Server exited.")
}
