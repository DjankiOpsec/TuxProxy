package tor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// ManagerOptions provides granular configuration for Tor process supervisor
type ManagerOptions struct {
	BindAddress      string // e.g. "127.0.0.1" or "10.200.1.1"
	SessionID        string // Unique session identifier
	Ephemeral        bool   // Ephemeral data dir
	UseControlSocket bool   // Prefer Unix domain socket over TCP ControlPort
	UseCookieAuth    bool   // Require CookieAuthentication 1
	SocksPort        int
	HTTPPort         int
	DNSPort          int
	ControlPort      int
}

// Manager supervises the Tor daemon process lifecycle with zero-leak hardening
type Manager struct {
	cfg               *config.Config
	opts              ManagerOptions
	cmd               *exec.Cmd
	runtimeDir        string
	dataDir           string
	torrcPath         string
	controlSocketPath string
	cookieAuthPath    string
	bindAddress       string
	socksPort         int
	httpPort          int
	dnsPort           int
	controlPort       int
	bootstrapped      bool
	isEphemeral       bool
	mu                sync.Mutex
	stopChan          chan struct{}
	watchdogOnce      sync.Once
	watchdogErrChan   chan error
}

// NewManager creates a new Tor process manager with default options (backward-compatible)
func NewManager(cfg *config.Config, ephemeral bool) (*Manager, error) {
	sessionID := generateSessionID()
	return NewManagerWithOptions(cfg, ManagerOptions{
		BindAddress:      "127.0.0.1",
		SessionID:        sessionID,
		Ephemeral:        ephemeral || cfg.Ephemeral,
		UseControlSocket: true,
		UseCookieAuth:    true,
		SocksPort:        cfg.SocksPort,
		HTTPPort:         cfg.HTTPPort,
		DNSPort:          cfg.DNSPort,
		ControlPort:      cfg.ControlPort,
	})
}

// NewManagerWithOptions creates a fully customized, hardened Tor manager
func NewManagerWithOptions(cfg *config.Config, opts ManagerOptions) (*Manager, error) {
	if opts.SessionID == "" {
		opts.SessionID = generateSessionID()
	}
	if opts.BindAddress == "" {
		opts.BindAddress = "127.0.0.1"
	}

	runtimeDir, err := createSecureRuntimeDir(opts.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure runtime dir: %w", err)
	}

	var dataDir string
	if opts.Ephemeral {
		dataDir, err = os.MkdirTemp("", fmt.Sprintf("tuxproxy-data-%s-*", opts.SessionID))
		if err != nil {
			_ = os.RemoveAll(runtimeDir)
			return nil, fmt.Errorf("failed to create ephemeral data dir: %w", err)
		}
		_ = os.Chmod(dataDir, 0700)
	} else {
		dataDir = config.GetDataDir()
	}

	socksPort := opts.SocksPort
	if socksPort == 0 || !IsPortAvailable(socksPort) {
		socksPort = FindAvailablePort(9050)
	}

	httpPort := opts.HTTPPort
	if httpPort == 0 || !IsPortAvailable(httpPort) {
		httpPort = FindAvailablePort(9080)
	}

	dnsPort := opts.DNSPort
	if dnsPort == 0 || !IsPortAvailable(dnsPort) {
		dnsPort = FindAvailablePort(9053)
	}

	controlPort := opts.ControlPort
	if !opts.UseControlSocket && (controlPort == 0 || !IsPortAvailable(controlPort)) {
		controlPort = FindAvailablePort(9051)
	}

	var controlSocketPath string
	var cookieAuthPath string
	if opts.UseControlSocket {
		controlSocketPath = filepath.Join(runtimeDir, "control.sock")
		// Clean up dead stale socket if it exists
		if err := cleanupStaleSocket(controlSocketPath); err != nil {
			_ = os.RemoveAll(runtimeDir)
			return nil, err
		}
	}
	if opts.UseCookieAuth {
		cookieAuthPath = filepath.Join(runtimeDir, "control_auth_cookie")
	}

	return &Manager{
		cfg:               cfg,
		opts:              opts,
		runtimeDir:        runtimeDir,
		dataDir:           dataDir,
		bindAddress:       opts.BindAddress,
		socksPort:         socksPort,
		httpPort:          httpPort,
		dnsPort:           dnsPort,
		controlPort:       controlPort,
		controlSocketPath: controlSocketPath,
		cookieAuthPath:    cookieAuthPath,
		isEphemeral:       opts.Ephemeral,
		stopChan:          make(chan struct{}),
		watchdogErrChan:   make(chan error, 2),
	}, nil
}

// Start launches Tor, streams bootstrap progress, and validates listeners
func (m *Manager) Start(onProgress func(percent int, message string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	torrcOpts := TorrcOptions{
		DataDir:           m.dataDir,
		BindAddress:       m.bindAddress,
		SocksPort:         m.socksPort,
		HTTPPort:          m.httpPort,
		DNSPort:           m.dnsPort,
		ControlPort:       m.controlPort,
		ControlSocketPath: m.controlSocketPath,
		CookieAuthFile:    m.cookieAuthPath,
		UseCookieAuth:     m.opts.UseCookieAuth,
	}

	torrcContent := BuildTorrcWithOptions(m.cfg, torrcOpts)
	m.torrcPath = filepath.Join(m.runtimeDir, "torrc")
	if err := os.WriteFile(m.torrcPath, []byte(torrcContent), 0600); err != nil {
		return fmt.Errorf("failed to write torrc: %w", err)
	}

	torBin := m.cfg.TorBinaryPath
	if torBin == "" {
		torBin = "tor"
	}

	cmd := exec.Command(torBin, "--defaults-torrc", "/dev/null", "-f", m.torrcPath)

	// Clean environment: scrub outer proxy variables
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

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

	select {
	case err := <-bootstrapDone:
		if err != nil {
			_ = m.Stop()
			return err
		}
	case <-time.After(90 * time.Second):
		_ = m.Stop()
		return fmt.Errorf("tor bootstrap timed out after 90 seconds (check bridge/network connectivity)")
	}

	// Verify listener bindings and perform synthetic handshake
	if err := m.VerifyListeners(); err != nil {
		_ = m.Stop()
		return fmt.Errorf("tor listeners verification failed: %w", err)
	}

	return nil
}

// VerifyListeners audits listener IP bindings via Control interface and performs synthetic handshakes
func (m *Manager) VerifyListeners() error {
	conn, err := m.dialControl()
	if err != nil {
		return fmt.Errorf("unable to connect to tor control interface: %w", err)
	}
	defer conn.Close()

	if err := m.authenticateControl(conn); err != nil {
		return fmt.Errorf("control authentication failed: %w", err)
	}

	reader := bufio.NewReader(conn)

	// Check SOCKS listeners
	_, _ = conn.Write([]byte("GETINFO net/listeners/socks\r\n"))
	socksResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(socksResp, "250") {
		return fmt.Errorf("failed to query socks listeners: %s", strings.TrimSpace(socksResp))
	}
	if strings.Contains(socksResp, "0.0.0.0") {
		return fmt.Errorf("critical security violation: Tor SOCKS listener is bound to 0.0.0.0")
	}

	// Check DNS listeners
	if m.dnsPort > 0 {
		_, _ = conn.Write([]byte("GETINFO net/listeners/dns\r\n"))
		dnsResp, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(dnsResp, "250") {
			return fmt.Errorf("failed to query dns listeners: %s", strings.TrimSpace(dnsResp))
		}
		if strings.Contains(dnsResp, "0.0.0.0") {
			return fmt.Errorf("critical security violation: Tor DNS listener is bound to 0.0.0.0")
		}
	}

	// Synthetic SOCKS5 Handshake: send \x05\x01\x00 -> expect \x05\x00
	if err := m.syntheticSocksHandshake(); err != nil {
		return fmt.Errorf("synthetic SOCKS5 handshake failed: %w", err)
	}

	// Synthetic DNS Query check
	if m.dnsPort > 0 {
		if err := m.syntheticDNSQuery(); err != nil {
			return fmt.Errorf("synthetic DNS query check failed: %w", err)
		}
	}

	return nil
}

// StartWatchdog launches event-driven supervision with 0ms reaction delay upon Tor crash or termination
func (m *Manager) StartWatchdog(ctx context.Context, onCrash func(err error)) {
	m.watchdogOnce.Do(func() {
		go func() {
			// Routine 1: Wait on cmd.Process
			procErrChan := make(chan error, 1)
			go func() {
				if m.cmd != nil {
					procErrChan <- m.cmd.Wait()
				}
			}()

			// Routine 2: Blocking EOF detection on ControlSocket
			sockErrChan := make(chan error, 1)
			go func() {
				ctrlConn, err := m.dialControl()
				if err != nil {
					sockErrChan <- err
					return
				}
				defer ctrlConn.Close()

				buf := make([]byte, 1)
				// Blocking read: returns io.EOF / error immediately when Tor dies
				_, readErr := ctrlConn.Read(buf)
				sockErrChan <- readErr
			}()

			var triggerErr error
			select {
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			case err := <-procErrChan:
				triggerErr = fmt.Errorf("tor process exited unexpectedly: %w", err)
			case err := <-sockErrChan:
				triggerErr = fmt.Errorf("tor control socket disconnected unexpectedly: %w", err)
			}

			if onCrash != nil {
				onCrash(triggerErr)
			}
		}()
	})
}

// Stop cleanly terminates Tor, wipes cookie, and removes temporary runtime resources
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.stopChan:
		// already stopped
	default:
		close(m.stopChan)
	}

	if m.cmd != nil && m.cmd.Process != nil {
		pgid, err := syscall.Getpgid(m.cmd.Process.Pid)
		if err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = m.cmd.Process.Signal(syscall.SIGTERM)
		}

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

	// Securely wipe cookie file
	if m.cookieAuthPath != "" {
		if data, err := os.ReadFile(m.cookieAuthPath); err == nil {
			zeroes := make([]byte, len(data))
			_ = os.WriteFile(m.cookieAuthPath, zeroes, 0600)
		}
		_ = os.Remove(m.cookieAuthPath)
	}

	if m.controlSocketPath != "" {
		_ = os.Remove(m.controlSocketPath)
	}

	if m.runtimeDir != "" {
		_ = os.RemoveAll(m.runtimeDir)
	}

	if m.isEphemeral && m.dataDir != "" {
		_ = os.RemoveAll(m.dataDir)
	}

	return nil
}

// SignalNewnym triggers circuit rotation via authenticated Control interface
func (m *Manager) SignalNewnym() error {
	conn, err := m.dialControl()
	if err != nil {
		return fmt.Errorf("unable to connect to control interface: %w", err)
	}
	defer conn.Close()

	if err := m.authenticateControl(conn); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	_, _ = conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	reader := bufio.NewReader(conn)
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("newnym signal failed: %s", strings.TrimSpace(resp))
	}
	return nil
}

// dialControl connects via Unix domain socket if configured, or TCP fallback
func (m *Manager) dialControl() (net.Conn, error) {
	if m.controlSocketPath != "" {
		return net.DialTimeout("unix", m.controlSocketPath, 2*time.Second)
	}
	return net.DialTimeout("tcp", net.JoinHostPort(m.bindAddress, strconv.Itoa(m.controlPort)), 2*time.Second)
}

// authenticateControl sends cookie or empty authentication
func (m *Manager) authenticateControl(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	if m.opts.UseCookieAuth && m.cookieAuthPath != "" {
		info, err := os.Lstat(m.cookieAuthPath)
		if err != nil {
			return fmt.Errorf("failed to stat cookie file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("security alert: cookie file is a symbolic link")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if stat.Uid != uint32(os.Getuid()) {
				return fmt.Errorf("security alert: cookie file owner UID mismatch (%d != %d)", stat.Uid, os.Getuid())
			}
		}

		cookieBytes, err := os.ReadFile(m.cookieAuthPath)
		if err != nil {
			return fmt.Errorf("failed to read cookie file: %w", err)
		}
		cookieHex := strings.ToUpper(hex.EncodeToString(cookieBytes))
		authCmd := fmt.Sprintf("AUTHENTICATE %s\r\n", cookieHex)
		if _, err := conn.Write([]byte(authCmd)); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte("AUTHENTICATE \"\"\r\n")); err != nil {
			return err
		}
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read error during auth: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("auth rejected: %s", strings.TrimSpace(resp))
	}
	return nil
}

// syntheticSocksHandshake verifies SOCKS5 port readiness by exchanging greeting packets
func (m *Manager) syntheticSocksHandshake() error {
	addr := net.JoinHostPort(m.bindAddress, strconv.Itoa(m.socksPort))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to socks listener (%s): %w", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Send SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("failed to write socks greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read socks greeting response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("unexpected socks response: %x", resp)
	}
	return nil
}

// syntheticDNSQuery verifies Tor DNSPort readiness by transmitting an RFC 1035 UDP query
func (m *Manager) syntheticDNSQuery() error {
	addr := net.JoinHostPort(m.bindAddress, strconv.Itoa(m.dnsPort))
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to dns listener (%s): %w", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Minimal valid DNS query packet for "check.torproject.org" (Type A, Class IN)
	queryPacket := []byte{
		0x13, 0x37, // ID
		0x01, 0x00, // Flags: Standard query, recursion desired
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// QNAME: 5 check 10 torproject 3 org 0
		0x05, 'c', 'h', 'e', 'c', 'k',
		0x0a, 't', 'o', 'r', 'p', 'r', 'o', 'j', 'e', 'c', 't',
		0x03, 'o', 'r', 'g', 0x00,
		0x00, 0x01, // QTYPE: A (1)
		0x00, 0x01, // QCLASS: IN (1)
	}

	if _, err := conn.Write(queryPacket); err != nil {
		return fmt.Errorf("failed to send test dns packet: %w", err)
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("failed to receive dns response from tor dnsport: %w", err)
	}
	if n < 12 {
		return fmt.Errorf("dns response too short (%d bytes)", n)
	}
	// Check matching transaction ID and QR bit
	if respBuf[0] != 0x13 || respBuf[1] != 0x37 {
		return fmt.Errorf("dns response ID mismatch")
	}
	if respBuf[2]&0x80 == 0 {
		return fmt.Errorf("dns response QR flag not set")
	}

	return nil
}

// Accessors
func (m *Manager) SocksAddr() string {
	return net.JoinHostPort(m.bindAddress, strconv.Itoa(m.socksPort))
}

func (m *Manager) HTTPAddr() string {
	return net.JoinHostPort(m.bindAddress, strconv.Itoa(m.httpPort))
}

func (m *Manager) DNSAddr() string {
	return net.JoinHostPort(m.bindAddress, strconv.Itoa(m.dnsPort))
}

func (m *Manager) ControlSocketPath() string {
	return m.controlSocketPath
}

func (m *Manager) Ports() (socks, http, dns, control int) {
	return m.socksPort, m.httpPort, m.dnsPort, m.controlPort
}

func (m *Manager) IsBootstrapped() bool {
	return m.bootstrapped
}

// Helper: generateSessionID generates an 8-character hex string
func generateSessionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper: createSecureRuntimeDir creates 0700 runtime directory with path symlink audit
func createSecureRuntimeDir(sessionID string) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}

	dir := filepath.Join(base, "tuxproxy", fmt.Sprintf("session-%s", sessionID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Verify permissions and ownership
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("failed to lstat runtime directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("security alert: runtime directory is a symlink: %s", dir)
	}
	if info.Mode().Perm() != 0700 {
		_ = os.Chmod(dir, 0700)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return "", fmt.Errorf("security alert: runtime directory owner UID mismatch (%d != %d)", stat.Uid, os.Getuid())
		}
	}

	return dir, nil
}

// Helper: cleanupStaleSocket checks if a socket is alive before removing
func cleanupStaleSocket(socketPath string) error {
	if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
		return nil
	}

	// Probe if existing instance is listening
	conn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("active Tor instance is already listening on socket: %s", socketPath)
	}

	// Socket exists but nobody is listening -> stale socket, safe to delete
	return os.Remove(socketPath)
}
