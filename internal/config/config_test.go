package config

import (
	"encoding/json"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ExitCountry != "us" {
		t.Errorf("expected exit_country 'us', got '%s'", cfg.ExitCountry)
	}
	if cfg.BridgeType != "snowflake" {
		t.Errorf("expected bridge_type 'snowflake', got '%s'", cfg.BridgeType)
	}
	if cfg.SocksPort != 9050 {
		t.Errorf("expected socks_port 9050, got %d", cfg.SocksPort)
	}
	if !cfg.DisableIPv6 || !cfg.SafeLogging || !cfg.PreventWebRTCLeak || !cfg.PreventDNSLeak {
		t.Errorf("expected all zero-leak OPSEC flags enabled by default")
	}
	if cfg.TorBinaryPath == "" {
		t.Errorf("expected tor_binary_path to be detected")
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	if parsed.ExitCountry != cfg.ExitCountry || parsed.SocksPort != cfg.SocksPort {
		t.Errorf("deserialized config does not match original")
	}
}

func TestCountryDisplay(t *testing.T) {
	cfg := &Config{ExitCountry: "us"}
	if cfg.CountryDisplay() != "США [US]" {
		t.Errorf("unexpected country display: %s", cfg.CountryDisplay())
	}
	cfg.ExitCountry = "any"
	if cfg.CountryDisplay() != "Любая страна [Оптимальный маршрут]" {
		t.Errorf("unexpected country display: %s", cfg.CountryDisplay())
	}
}
