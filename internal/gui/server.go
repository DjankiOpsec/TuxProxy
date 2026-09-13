package gui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"
	"tuxproxy/internal/banner"
	"tuxproxy/internal/config"
	"tuxproxy/internal/shell"
	"tuxproxy/internal/tor"
	"tuxproxy/internal/verifier"
)

// Server encapsulates the Web GUI HTTP server state
type Server struct {
	cfg         *config.Config
	torMgr      *tor.Manager
	port        int
	mu          sync.Mutex
	isBooting   bool
	bootPct     int
	bootMsg     string
	currentIP   string
	currentGeo  string
	currentCity string
}

// StartWebServer starts the graphical Web GUI settings studio on 127.0.0.1:9099
func StartWebServer(cfg *config.Config, autoOpen bool) error {
	s := &Server{
		cfg:  cfg,
		port: tor.FindAvailablePort(9099),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/reset", s.handleConfigReset)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/hook/enable", s.handleHookEnable)
	mux.HandleFunc("/api/hook/disable", s.handleHookDisable)
	mux.HandleFunc("/api/hook/status", s.handleHookStatus)
	mux.HandleFunc("/api/test", s.handleTest)
	mux.HandleFunc("/api/newnym", s.handleNewnym)
	mux.HandleFunc("/api/daemon/start", s.handleDaemonStart)
	mux.HandleFunc("/api/daemon/stop", s.handleDaemonStop)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	url := fmt.Sprintf("http://%s", addr)

	fmt.Println(banner.BannerString())
	fmt.Printf("%s Центр настроек TuxProxy (Web GUI) запущен: %s%s%s\n",
		banner.TagOK("GUI"), banner.Bold+banner.BrightCyan, url, banner.Reset)
	fmt.Printf("%s Нажмите [Ctrl+C] для завершения сеанса конфигуратора\n\n", banner.TagInfo("СЛУЖБА"))

	if autoOpen {
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = exec.Command("xdg-open", url).Start()
		}()
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return server.ListenAndServe()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(DashboardHTML))
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.Method == http.MethodPost {
		var incoming config.Config
		if err := json.NewDecoder(r.Body).Decode(&incoming); err == nil {
			oldHook := s.cfg.TerminalAutoHook

			// Обновление параметров
			s.cfg.ExitCountry = incoming.ExitCountry
			s.cfg.StrictNodes = incoming.StrictNodes
			s.cfg.ExcludeNodes = incoming.ExcludeNodes
			if incoming.NumEntryGuards > 0 {
				s.cfg.NumEntryGuards = incoming.NumEntryGuards
			}

			s.cfg.BridgeType = incoming.BridgeType
			s.cfg.CustomBridges = incoming.CustomBridges
			s.cfg.SnowflakeURL = incoming.SnowflakeURL
			s.cfg.SnowflakeFront = incoming.SnowflakeFront
			s.cfg.SnowflakeAMPCache = incoming.SnowflakeAMPCache

			if incoming.SocksPort > 0 {
				s.cfg.SocksPort = incoming.SocksPort
			}
			if incoming.HTTPPort > 0 {
				s.cfg.HTTPPort = incoming.HTTPPort
			}
			if incoming.DNSPort > 0 {
				s.cfg.DNSPort = incoming.DNSPort
			}
			if incoming.ControlPort > 0 {
				s.cfg.ControlPort = incoming.ControlPort
			}

			s.cfg.DisableIPv6 = incoming.DisableIPv6
			s.cfg.SafeLogging = incoming.SafeLogging
			s.cfg.PreventWebRTCLeak = incoming.PreventWebRTCLeak
			s.cfg.PreventDNSLeak = incoming.PreventDNSLeak
			s.cfg.ForceProxychains = incoming.ForceProxychains
			s.cfg.Ephemeral = incoming.Ephemeral

			if incoming.UniversalAppMode != "" {
				s.cfg.UniversalAppMode = incoming.UniversalAppMode
			}
			s.cfg.JavaProxySupport = incoming.JavaProxySupport

			s.cfg.TerminalAutoHook = incoming.TerminalAutoHook
			s.cfg.TerminalAutoStartDaemon = incoming.TerminalAutoStartDaemon
			s.cfg.ShowPromptIndicator = incoming.ShowPromptIndicator

			if incoming.TorBinaryPath != "" {
				s.cfg.TorBinaryPath = incoming.TorBinaryPath
			}
			if incoming.SnowflakePath != "" {
				s.cfg.SnowflakePath = incoming.SnowflakePath
			}
			if incoming.LyrebirdPath != "" {
				s.cfg.LyrebirdPath = incoming.LyrebirdPath
			}
			if incoming.WebTunnelPath != "" {
				s.cfg.WebTunnelPath = incoming.WebTunnelPath
			}
			if incoming.ProxychainsPath != "" {
				s.cfg.ProxychainsPath = incoming.ProxychainsPath
			}

			_ = s.cfg.Save()

			// Синхронизация системного хука при изменении опции
			if s.cfg.TerminalAutoHook != oldHook {
				if s.cfg.TerminalAutoHook {
					_ = shell.InstallHook()
				} else {
					_ = shell.RemoveHook()
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.cfg)
}

func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	defaultCfg := config.DefaultConfig()
	*s.cfg = *defaultCfg
	_ = s.cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.cfg)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	socksPort := s.cfg.SocksPort
	if s.torMgr != nil {
		socksPort, _, _, _ = s.torMgr.Ports()
	}

	active := (s.torMgr != nil && s.torMgr.IsBootstrapped()) || !tor.IsPortAvailable(socksPort)

	resp := map[string]interface{}{
		"active":         active,
		"bootstrapping":  s.isBooting,
		"percent":        s.bootPct,
		"message":        s.bootMsg,
		"ip":             s.currentIP,
		"country":        s.currentGeo,
		"city":           s.currentCity,
		"port":           socksPort,
		"hook_installed": shell.IsHookInstalled(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHookEnable(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := shell.InstallHook()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	s.cfg.TerminalAutoHook = true
	_ = s.cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "installed": true})
}

func (s *Server) handleHookDisable(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := shell.RemoveHook()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	s.cfg.TerminalAutoHook = false
	_ = s.cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "installed": false})
}

func (s *Server) handleHookStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"installed": shell.IsHookInstalled(),
		"enabled":   s.cfg.TerminalAutoHook,
	})
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	socksPort := s.cfg.SocksPort
	if s.torMgr != nil {
		socksPort, _, _, _ = s.torMgr.Ports()
	}
	s.mu.Unlock()

	// Если шлюз не запущен, кратковременно запускаем для проверки
	if tor.IsPortAvailable(socksPort) && s.torMgr == nil {
		mgr, err := tor.NewManager(s.cfg, true)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		s.mu.Lock()
		s.isBooting = true
		s.bootPct = 0
		s.mu.Unlock()

		err = mgr.Start(func(pct int, msg string) {
			s.mu.Lock()
			s.bootPct = pct
			s.bootMsg = msg
			s.mu.Unlock()
		})

		s.mu.Lock()
		s.isBooting = false
		s.mu.Unlock()

		if err != nil {
			_ = mgr.Stop()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}

		s.mu.Lock()
		s.torMgr = mgr
		socksPort, _, _, _ = mgr.Ports()
		s.mu.Unlock()
	}

	report := verifier.VerifyEgress(socksPort, 12*time.Second)

	s.mu.Lock()
	if report.IP != "" {
		s.currentIP = report.IP
		s.currentGeo = report.Country
		s.currentCity = report.City
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":      report.IP,
		"country": report.Country,
		"city":    report.City,
		"org":     report.Org,
		"is_tor":  report.IsTor,
		"latency": report.Latency.String(),
		"error": func() string {
			if report.Error != nil {
				return report.Error.Error()
			}
			return ""
		}(),
	})
}

func (s *Server) handleNewnym(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	mgr := s.torMgr
	controlPort := s.cfg.ControlPort
	s.mu.Unlock()

	if mgr != nil {
		_ = mgr.SignalNewnym()
	} else if !tor.IsPortAvailable(controlPort) {
		tempMgr, err := tor.NewManager(&config.Config{ControlPort: controlPort}, false)
		if err == nil {
			_ = tempMgr.SignalNewnym()
		}
	}

	time.Sleep(1 * time.Second)
	s.mu.Lock()
	socksPort := s.cfg.SocksPort
	if s.torMgr != nil {
		socksPort, _, _, _ = s.torMgr.Ports()
	}
	s.mu.Unlock()

	go func() {
		rep := verifier.VerifyEgress(socksPort, 8*time.Second)
		s.mu.Lock()
		if rep.IP != "" {
			s.currentIP = rep.IP
			s.currentGeo = rep.Country
			s.currentCity = rep.City
		}
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func (s *Server) handleDaemonStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.torMgr != nil && s.torMgr.IsBootstrapped() {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "already_running": true})
		return
	}

	mgr, err := tor.NewManager(s.cfg, s.cfg.Ephemeral)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	s.torMgr = mgr
	s.isBooting = true
	s.bootPct = 0

	go func() {
		_ = mgr.Start(func(pct int, msg string) {
			s.mu.Lock()
			s.bootPct = pct
			s.bootMsg = msg
			s.mu.Unlock()
		})
		s.mu.Lock()
		s.isBooting = false
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func (s *Server) handleDaemonStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.torMgr != nil {
		_ = s.torMgr.Stop()
		s.torMgr = nil
	}
	s.isBooting = false
	s.currentIP = ""
	s.currentGeo = ""
	s.currentCity = ""

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}
