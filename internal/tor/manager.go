package tor

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"tuxproxy/internal/config"
)

var bootstrapRegex = regexp.MustCompile(`Bootstrapped\s+(\d+)%\s*(?:\(([^)]+)\))?:\s*(.*)`)

// Manager supervises the Tor daemon process lifecycle
type Manager struct {
	cfg          *config.Config
	cmd          *exec.Cmd
	runtimeDir   string
	dataDir      string
	torrcPath    string
	socksPort    int
	httpPort     int
	dnsPort      int
	controlPort  int
	bootstrapped bool
	isEphemeral  bool
	mu           sync.Mutex
	stopChan     chan struct{}
}

// NewManager creates a new Tor process manager
func NewManager(cfg *config.Config, ephemeral bool) (*Manager, error) {
	runtimeDir, err := os.MkdirTemp("", "tuxproxy-rt-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create runtime dir: %w", err)
	}

	var dataDir string
	if ephemeral || cfg.Ephemeral {
		dataDir, err = os.MkdirTemp("", "tuxproxy-data-*")
		if err != nil {
			_ = os.RemoveAll(runtimeDir)
			return nil, fmt.Errorf("failed to create ephemeral data dir: %w", err)
		}
	} else {
		dataDir = config.GetDataDir()
	}

	// Dynamic port assignment to prevent collision
	socksPort := cfg.SocksPort
	if socksPort == 0 || !IsPortAvailable(socksPort) {
		socksPort = FindAvailablePort(9050)
	}

	httpPort := cfg.HTTPPort
	if httpPort == 0 || !IsPortAvailable(httpPort) {
		httpPort = FindAvailablePort(9080)
	}

	dnsPort := cfg.DNSPort
	if dnsPort == 0 || !IsPortAvailable(dnsPort) {
		dnsPort = FindAvailablePort(9053)
	}

	controlPort := cfg.ControlPort
	if controlPort == 0 || !IsPortAvailable(controlPort) {
		controlPort = FindAvailablePort(9051)
	}

	return &Manager{
		cfg:         cfg,
		runtimeDir:  runtimeDir,
		dataDir:     dataDir,
		socksPort:   socksPort,
		httpPort:    httpPort,
		dnsPort:     dnsPort,
		controlPort: controlPort,
		isEphemeral: ephemeral || cfg.Ephemeral,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start launches Tor, streams bootstrap progress, and blocks until 100% or failure
func (m *Manager) Start(onProgress func(percent int, message string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Write torrc
	torrcContent := BuildTorrc(m.cfg, m.dataDir, m.socksPort, m.httpPort, m.dnsPort, m.controlPort)
	m.torrcPath = filepath.Join(m.runtimeDir, "torrc")
	if err := os.WriteFile(m.torrcPath, []byte(torrcContent), 0600); err != nil {
		return fmt.Errorf("failed to write torrc: %w", err)
	}

	torBin := m.cfg.TorBinaryPath
	if torBin == "" {
		torBin = "tor"
	}

	cmd := exec.Command(torBin, "--defaults-torrc", "/dev/null", "-f", m.torrcPath)

	// OPSEC & Anti-Inheritance: Strip any pre-existing outer proxy env vars
	cleanEnv := make([]string, 0, len(os.Environ()))
	for _, env := range os.Environ() {
		lower := strings.ToLower(env)
		if strings.HasPrefix(lower, "http_proxy=") ||
			strings.HasPrefix(lower, "https_proxy=") ||
			strings.HasPrefix(lower, "all_proxy=") ||
			strings.HasPrefix(lower, "socks_proxy=") ||
			strings.HasPrefix(lower, "ftp_proxy=") {
			continue
		}
		cleanEnv = append(cleanEnv, env)
	}
	cmd.Env = cleanEnv

	// Process group isolation for clean teardown of child pluggable transport binaries
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // Merge stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tor binary (%s): %w", torBin, err)
	}
	m.cmd = cmd

	bootstrapDone := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()

			if matches := bootstrapRegex.FindStringSubmatch(line); len(matches) > 1 {
				pct, _ := strconv.Atoi(matches[1])
				msg := matches[len(matches)-1]
				if onProgress != nil {
					onProgress(pct, msg)
				}
				if pct >= 100 {
					m.bootstrapped = true
					bootstrapDone <- nil
					return
				}
			}

			// Catch early fatal errors
			if strings.Contains(line, "[err]") || strings.Contains(line, "Failed to parse/validate config") {
				bootstrapDone <- fmt.Errorf("tor error: %s", line)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			bootstrapDone <- err
		} else if !m.bootstrapped {
			bootstrapDone <- fmt.Errorf("tor process terminated before completing bootstrap")
		}
	}()

	// Wait with timeout
	select {
	case err := <-bootstrapDone:
		if err != nil {
			_ = m.Stop()
			return err
		}
		return nil
	case <-time.After(90 * time.Second):
		_ = m.Stop()
		return fmt.Errorf("tor bootstrap timed out after 90 seconds (check your bridge settings)")
	}
}

// Stop cleanly terminates Tor and removes temporary runtime resources
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		pgid, err := syscall.Getpgid(m.cmd.Process.Pid)
		if err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = m.cmd.Process.Signal(syscall.SIGTERM)
		}

		// Wait up to 2 seconds
		done := make(chan error, 1)
		go func() {
			done <- m.cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if pgid != 0 {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = m.cmd.Process.Kill()
			}
		}
	}

	// Clean up runtime dir
	if m.runtimeDir != "" {
		_ = os.RemoveAll(m.runtimeDir)
	}

	// If ephemeral, clean up data dir too
	if m.isEphemeral && m.dataDir != "" {
		_ = os.RemoveAll(m.dataDir)
	}

	return nil
}

// SignalNewnym triggers circuit rotation via Tor ControlPort
func (m *Manager) SignalNewnym() error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", m.controlPort), 2*time.Second)
	if err != nil {
		return fmt.Errorf("unable to connect to tor control port: %w", err)
	}
	defer conn.Close()

	// Authenticate (empty cookie/pass by default in our torrc)
	_, _ = conn.Write([]byte("AUTHENTICATE \"\"\r\n"))
	reader := bufio.NewReader(conn)
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("control auth failed: %s", strings.TrimSpace(resp))
	}

	_, _ = conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("newnym signal failed: %s", strings.TrimSpace(resp))
	}

	return nil
}

// Accessors
func (m *Manager) SocksAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.socksPort)
}

func (m *Manager) HTTPAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.httpPort)
}

func (m *Manager) DNSAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.dnsPort)
}

func (m *Manager) Ports() (socks, http, dns, control int) {
	return m.socksPort, m.httpPort, m.dnsPort, m.controlPort
}

func (m *Manager) IsBootstrapped() bool {
	return m.bootstrapped
}
