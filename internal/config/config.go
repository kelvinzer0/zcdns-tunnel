package config

import (
	"github.com/spf13/viper"
)

// GossipConfig holds the configuration for the gossip protocol
type GossipConfig struct {
	ProbeInterval string `mapstructure:"probe_interval"`
	ProbeTimeout  string `mapstructure:"probe_timeout"`
}

// ServerConfig holds all the configuration for the server
type ServerConfig struct {
	SshListenAddr      string `mapstructure:"ssh_listen_addr"`
	SshHostKeyPath     string `mapstructure:"ssh_host_key_path"`
	ValidationDomain   string `mapstructure:"validation_domain"`
	InterNodeSSHKeyPath string `mapstructure:"inter_node_ssh_key_path"`
	Gossip             GossipConfig `mapstructure:"gossip"`
}

// LoadServerConfig loads the server configuration from a file
func LoadServerConfig(path string) (ServerConfig, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()

	// Set default values for gossip configuration
	viper.SetDefault("gossip.probe_interval", "1s")
	viper.SetDefault("gossip.probe_timeout", "500ms")

	var config ServerConfig
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}

	if err := viper.Unmarshal(&config); err != nil {
		return config, err
	}

	return config, nil
}
