package config

import (
	"os"
	"path/filepath"
)

// GetConfigDir returns ~/.config/tuxproxy (or XDG_CONFIG_HOME/tuxproxy)
func GetConfigDir() string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "tuxproxy-config")
		}
		configHome = filepath.Join(home, ".config")
	}
	dir := filepath.Join(configHome, "tuxproxy")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// GetConfigFile returns the full path to config.json
func GetConfigFile() string {
	return filepath.Join(GetConfigDir(), "config.json")
}

// GetDataDir returns ~/.local/share/tuxproxy/tor_data (or XDG_DATA_HOME/tuxproxy/tor_data)
func GetDataDir() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "tuxproxy-data")
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(dataHome, "tuxproxy", "tor_data")
	_ = os.MkdirAll(dir, 0700)
	return dir
}
