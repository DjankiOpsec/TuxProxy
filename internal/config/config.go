package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// Config представляет расширенную схему настроек TuxProxy
type Config struct {
	// Маршрутизация и Геолокация
	ExitCountry       string   `json:"exit_country"`        // Двухбуквенный ISO-код страны выхода (или "any")
	StrictNodes       bool     `json:"strict_nodes"`        // Строгая привязка: разрыв при отсутствии целевых релеев
	ExcludeNodes      string   `json:"exclude_nodes"`       // Исключаемые страны/узлы, например "{ru},{by}"
	NumEntryGuards    int      `json:"num_entry_guards"`    // Число входных узлов (по умолчанию 1)

	// Обход блокировок (Pluggable Transports)
	BridgeType        string   `json:"bridge_type"`         // "none", "snowflake", "obfs4", "webtunnel", "custom"
	CustomBridges     []string `json:"custom_bridges"`      // Пользовательские строки мостов
	SnowflakeURL      string   `json:"snowflake_url"`       // URL сигнального брокера Snowflake
	SnowflakeFront    string   `json:"snowflake_front"`     // Домен фронтинга (например www.google.com)
	SnowflakeAMPCache string   `json:"snowflake_ampcache"`  // URL проксирования через Google AMP Cache

	// Сетевые слушатели (Порты)
	SocksPort         int      `json:"socks_port"`          // Локальный SOCKS5h порт (по умолчанию 9050)
	HTTPPort          int      `json:"http_port"`           // Локальный HTTP CONNECT порт (по умолчанию 9080)
	DNSPort           int      `json:"dns_port"`            // Локальный DNS-резолвер Tor (по умолчанию 9053)
	ControlPort       int      `json:"control_port"`        // Порт управления Tor ControlPort (по умолчанию 9051)

	// Безопасность и предотвращение утечек (Zero-Leak OPSEC)
	DisableIPv6       bool     `json:"disable_ipv6"`        // Отключение dual-stack IPv6 (ClientUseIPv6 0)
	SafeLogging       bool     `json:"safe_logging"`        // Очистка IP-адресов в служебных логах Tor
	PreventWebRTCLeak bool     `json:"prevent_webrtc_leak"` // Подавление не-проксированного WebRTC UDP трафика
	PreventDNSLeak    bool     `json:"prevent_dns_leak"`    // Блокировка локального DNS через socks5h и host-resolver-rules
	ForceProxychains  bool     `json:"force_proxychains"`   // Принудительный перехват всех процессов через proxychains4
	Ephemeral         bool     `json:"ephemeral"`           // Работа исключительно в RAM/tmpfs (без следов на диске)

	// Универсальная изоляция приложений
	UniversalAppMode  string   `json:"universal_app_mode"`  // "auto", "proxychains", "env", "electron"
	JavaProxySupport  bool     `json:"java_proxy_support"`  // Автоматическая инжекция _JAVA_OPTIONS для IntelliJ/Java

	// Интеграция с терминалом (Shell Hook)
	TerminalAutoHook        bool   `json:"terminal_auto_hook"`         // Автоподключение к каждой сессии терминала
	ShellType               string `json:"shell_type"`                 // "bash", "zsh", "fish", "auto"
	TerminalAutoStartDaemon bool   `json:"terminal_auto_start_daemon"` // Автозапуск демона в фоне при открытии терминала
	ShowPromptIndicator     bool   `json:"show_prompt_indicator"`      // Индикатор [tuxproxy:US] в строке приглашения терминала

	// Системные пути к бинарникам (автоопределение)
	TorBinaryPath   string `json:"tor_binary_path,omitempty"`
	SnowflakePath   string `json:"snowflake_path,omitempty"`
	LyrebirdPath    string `json:"lyrebird_path,omitempty"`
	WebTunnelPath   string `json:"webtunnel_path,omitempty"`
	ProxychainsPath string `json:"proxychains_path,omitempty"`
}

// DefaultSnowflakeBridges — актуальные официальные публичные мосты Snowflake проекта Tor
var DefaultSnowflakeBridges = []string{
	"Bridge snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72",
	"Bridge snowflake 192.0.2.4:1 8838024498816A039FCBBAB14E6E40A0843051FA",
}

// DefaultConfig генерирует эталонный набор параметров безопасности
func DefaultConfig() *Config {
	cfg := &Config{
		ExitCountry:             "us",
		StrictNodes:             true,
		ExcludeNodes:            "",
		NumEntryGuards:          1,
		BridgeType:              "snowflake", // По умолчанию Snowflake для пробития цензуры в РФ
		CustomBridges:           []string{},
		SnowflakeURL:            "https://snowflake-broker.torproject.net/",
		SnowflakeFront:          "www.google.com",
		SnowflakeAMPCache:       "https://cdn.ampproject.org/",
		SocksPort:               9050,
		HTTPPort:                9080,
		DNSPort:                 9053,
		ControlPort:             9051,
		DisableIPv6:             true,
		SafeLogging:             true,
		PreventWebRTCLeak:       true,
		PreventDNSLeak:          true,
		ForceProxychains:        false,
		Ephemeral:               false,
		UniversalAppMode:        "auto",
		JavaProxySupport:        true,
		TerminalAutoHook:        false,
		ShellType:               "auto",
		TerminalAutoStartDaemon: true,
		ShowPromptIndicator:     true,
	}
	cfg.AutoDetectBinaries()
	return cfg
}

// AutoDetectBinaries сканирует систему на наличие бинарных файлов Tor и мостов
func (c *Config) AutoDetectBinaries() {
	if c.TorBinaryPath == "" {
		if path, err := exec.LookPath("tor"); err == nil {
			c.TorBinaryPath = path
		} else {
			c.TorBinaryPath = "/usr/bin/tor"
		}
	}

	if c.SnowflakePath == "" {
		if path, err := exec.LookPath("snowflake-client"); err == nil {
			c.SnowflakePath = path
		} else if _, err := os.Stat("/usr/bin/snowflake-client"); err == nil {
			c.SnowflakePath = "/usr/bin/snowflake-client"
		}
	}

	if c.LyrebirdPath == "" {
		if path, err := exec.LookPath("lyrebird"); err == nil {
			c.LyrebirdPath = path
		} else if path, err := exec.LookPath("obfs4proxy"); err == nil {
			c.LyrebirdPath = path
		} else {
			home, _ := os.UserHomeDir()
			lyrebirdLocal := home + "/.local/bin/lyrebird"
			if _, err := os.Stat(lyrebirdLocal); err == nil {
				c.LyrebirdPath = lyrebirdLocal
			}
		}
	}

	if c.WebTunnelPath == "" {
		if path, err := exec.LookPath("webtunnel-client"); err == nil {
			c.WebTunnelPath = path
		} else if _, err := os.Stat("/usr/local/bin/webtunnel-client"); err == nil {
			c.WebTunnelPath = "/usr/local/bin/webtunnel-client"
		}
	}

	if c.ProxychainsPath == "" {
		if path, err := exec.LookPath("proxychains4"); err == nil {
			c.ProxychainsPath = path
		} else if path, err := exec.LookPath("proxychains"); err == nil {
			c.ProxychainsPath = path
		}
	}
}

// Load загружает конфигурацию из ~/.config/tuxproxy/config.json
func Load() (*Config, error) {
	configFile := GetConfigFile()
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		cfg := DefaultConfig()
		_ = cfg.Save()
		return cfg, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.AutoDetectBinaries()
	return cfg, nil
}

// Save сохраняет параметры в ~/.config/tuxproxy/config.json
func (c *Config) Save() error {
	configFile := GetConfigFile()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
}

// CountryDisplay возвращает стандартизированное наименование страны выхода
func (c *Config) CountryDisplay() string {
	cc := strings.ToLower(strings.TrimSpace(c.ExitCountry))
	switch cc {
	case "us":
		return "США [US]"
	case "de":
		return "Германия [DE]"
	case "nl":
		return "Нидерланды [NL]"
	case "ch":
		return "Швейцария [CH]"
	case "ca":
		return "Канада [CA]"
	case "gb", "uk":
		return "Великобритания [GB]"
	case "se":
		return "Швеция [SE]"
	case "sg":
		return "Сингапур [SG]"
	case "jp":
		return "Япония [JP]"
	case "fr":
		return "Франция [FR]"
	case "fi":
		return "Финляндия [FI]"
	case "any", "":
		return "Любая страна [Оптимальный маршрут]"
	default:
		return strings.ToUpper(cc)
	}
}
