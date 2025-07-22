package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"zcdns-tunnel/internal/config"
	"zcdns-tunnel/internal/server"
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
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Create a context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create and start the SSH server
	sshServer := server.NewSSHServer(cfg)
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
