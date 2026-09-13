package leak

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetNSConfig defines parameters for a dedicated zero-leak Network Namespace session
type NetNSConfig struct {
	SessionID    string
	SubnetID     int    // Subnet number between 10 and 250 (e.g. 42 -> 10.200.42.0/24)
	TargetUser   string // Non-root user to drop privileges to inside namespace
	TargetUID    uint32
	TargetGID    uint32
	TorSocksPort int // Tor SOCKS5 listener port on gateway (default 9050)
	TorDNSPort   int // Tor DNSPort on gateway (default 9053)
}

// SessionMetadata stores persistent state for crash recovery and GC reconciliation
type SessionMetadata struct {
	SessionID     string    `json:"session_id"`
	SubnetID      int       `json:"subnet_id"`
	PID           int       `json:"pid"`
	StartTime     uint64    `json:"starttime"` // Clock ticks from /proc/<pid>/stat
	NetNSName     string    `json:"netns_name"`
	VethHost      string    `json:"veth_host"`
	VethApp       string    `json:"veth_app"`
	ResolvConfDir string    `json:"resolv_conf_dir"`
	NFTTable      string    `json:"nft_table"`
	CreatedAt     time.Time `json:"created_at"`
}

// CommandRunner abstract execution for testability and logging
type CommandRunner func(name string, args ...string) ([]byte, error)

var defaultCommandRunner CommandRunner = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// NetNSEngine manages the kernel-level network and mount namespace isolation
type NetNSEngine struct {
	cfg      NetNSConfig
	runner   CommandRunner
	metaPath string
	active   bool
	mu       sync.Mutex
}

// NewNetNSEngine creates an instance of the kernel namespace isolator
func NewNetNSEngine(cfg NetNSConfig) *NetNSEngine {
	if cfg.TorSocksPort == 0 {
		cfg.TorSocksPort = 9050
	}
	if cfg.TorDNSPort == 0 {
		cfg.TorDNSPort = 9053
	}
	if cfg.SubnetID == 0 {
		cfg.SubnetID = 42
	}
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("%d", cfg.SubnetID)
	}

	// Detect target user for privilege drop if running under sudo
	if cfg.TargetUser == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			cfg.TargetUser = sudoUser
			if uidStr := os.Getenv("SUDO_UID"); uidStr != "" {
				if uid, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
					cfg.TargetUID = uint32(uid)
				}
			}
			if gidStr := os.Getenv("SUDO_GID"); gidStr != "" {
				if gid, err := strconv.ParseUint(gidStr, 10, 32); err == nil {
					cfg.TargetGID = uint32(gid)
				}
			}
		}
	}

	return &NetNSEngine{
		cfg:    cfg,
		runner: defaultCommandRunner,
	}
}

// SetCommandRunner allows injecting mock runners in tests
func (e *NetNSEngine) SetCommandRunner(r CommandRunner) {
	e.runner = r
}

// Names and paths helpers
func (e *NetNSEngine) NetNSName() string {
	return fmt.Sprintf("netns-tux-%s", e.cfg.SessionID)
}

func (e *NetNSEngine) VethHost() string {
	return fmt.Sprintf("veth-tux-%s", e.cfg.SessionID)
}

func (e *NetNSEngine) VethApp() string {
	return fmt.Sprintf("veth-app-%s", e.cfg.SessionID)
}

func (e *NetNSEngine) NFTTable() string {
	return fmt.Sprintf("tux_session_%s", e.cfg.SessionID)
}

func (e *NetNSEngine) GatewayIP() string {
	return fmt.Sprintf("10.200.%d.1", e.cfg.SubnetID)
}

func (e *NetNSEngine) AppIP() string {
	return fmt.Sprintf("10.200.%d.2", e.cfg.SubnetID)
}

func (e *NetNSEngine) ResolvConfDir() string {
	return fmt.Sprintf("/etc/netns/%s", e.NetNSName())
}

// Setup builds the entire fail-closed Network Namespace and nftables firewall
func (e *NetNSEngine) Setup() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.active {
		return nil
	}

	// 1. Check root / CAP_NET_ADMIN privileges
	if os.Geteuid() != 0 {
		return errors.New("netns-gateway profile requires root privileges or CAP_NET_ADMIN (run with sudo)")
	}

	nsName := e.NetNSName()
	vHost := e.VethHost()
	vApp := e.VethApp()
	gwIP := e.GatewayIP()
	appIP := e.AppIP()

	// 2. Create Network Namespace
	if out, err := e.runner("ip", "netns", "add", nsName); err != nil {
		return fmt.Errorf("failed to create netns %s: %s (%w)", nsName, string(out), err)
	}

	// Rollback guard in case of mid-flight failures
	success := false
	defer func() {
		if !success {
			_ = e.teardownInternal()
		}
	}()

	// 3. Bring up Loopback interface inside namespace (critical for Chromium/Electron/IPC)
	if out, err := e.runner("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("failed to bring up lo inside %s: %s (%w)", nsName, string(out), err)
	}

	// 4. Create veth pair
	if out, err := e.runner("ip", "link", "add", vHost, "type", "veth", "peer", "name", vApp); err != nil {
		return fmt.Errorf("failed to create veth pair (%s <-> %s): %s (%w)", vHost, vApp, string(out), err)
	}

	// 5. Move app end of veth into namespace
	if out, err := e.runner("ip", "link", "set", vApp, "netns", nsName); err != nil {
		return fmt.Errorf("failed to move %s into %s: %s (%w)", vApp, nsName, string(out), err)
	}

	// 6. Configure Host Gateway interface
	if out, err := e.runner("ip", "addr", "add", fmt.Sprintf("%s/24", gwIP), "dev", vHost); err != nil {
		return fmt.Errorf("failed to set ip on %s: %s (%w)", vHost, string(out), err)
	}
	if out, err := e.runner("ip", "link", "set", vHost, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s: %s (%w)", vHost, string(out), err)
	}

	// 7. Configure Namespace interface, default route, and sysctls
	if out, err := e.runner("ip", "netns", "exec", nsName, "ip", "addr", "add", fmt.Sprintf("%s/24", appIP), "dev", vApp, "scope", "global"); err != nil {
		return fmt.Errorf("failed to set ip on %s: %s (%w)", vApp, string(out), err)
	}
	if out, err := e.runner("ip", "netns", "exec", nsName, "ip", "link", "set", vApp, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s inside netns: %s (%w)", vApp, string(out), err)
	}
	if out, err := e.runner("ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", gwIP, "dev", vApp, "scope", "global"); err != nil {
		return fmt.Errorf("failed to add default route inside %s: %s (%w)", nsName, string(out), err)
	}

	// Disable IPv6 inside namespace to prevent dual-stack leakage
	_, _ = e.runner("ip", "netns", "exec", nsName, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1")
	_, _ = e.runner("ip", "netns", "exec", nsName, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1")
	// Disable Reverse Path Filtering inside namespace to allow Tor proxy responses
	_, _ = e.runner("ip", "netns", "exec", nsName, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	_, _ = e.runner("ip", "netns", "exec", nsName, "sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", vApp))

	// 8. Configure isolated DNS (/etc/netns/<name>/resolv.conf)
	resolvDir := e.ResolvConfDir()
	if err := os.MkdirAll(resolvDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", resolvDir, err)
	}
	resolvContent := fmt.Sprintf("# Generated by TuxProxy NetNS Engine\nnameserver %s\noptions edns0 trust-ad\n", gwIP)
	if err := os.WriteFile(filepath.Join(resolvDir, "resolv.conf"), []byte(resolvContent), 0644); err != nil {
		return fmt.Errorf("failed to write netns resolv.conf: %w", err)
	}

	// 9. Load nftables session table atomically via stdin
	nftRules := e.GenerateNFTRules()
	if err := e.applyNFTRules(nftRules); err != nil {
		return fmt.Errorf("failed to apply nftables ruleset: %w", err)
	}

	// 10. Record metadata with (PID, starttime) for GC
	if err := e.recordMetadata(); err != nil {
		return fmt.Errorf("failed to record session metadata: %w", err)
	}

	e.active = true
	success = true
	return nil
}

// GenerateNFTRules creates the atomic per-session nftables ruleset buffer
func (e *NetNSEngine) GenerateNFTRules() string {
	table := e.NFTTable()
	vHost := e.VethHost()
	gwIP := e.GatewayIP()
	appIP := e.AppIP()
	socksPort := e.cfg.TorSocksPort
	dnsPort := e.cfg.TorDNSPort

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("table inet %s {\n", table))

	// PREROUTING: Transparent DNS interception (UDP and TCP port 53) -> Tor DNSPort
	sb.WriteString("    chain prerouting {\n")
	sb.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" udp dport 53 dnat to %s:%d\n", vHost, gwIP, dnsPort))
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" tcp dport 53 dnat to %s:%d\n", vHost, gwIP, dnsPort))
	sb.WriteString("    }\n\n")

	// INPUT: Accept ONLY Tor SOCKS and Tor DNS from the namespace, drop everything else
	sb.WriteString("    chain input {\n")
	sb.WriteString("        type filter hook input priority filter; policy drop;\n")
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" ip saddr %s tcp dport %d accept\n", vHost, appIP, socksPort))
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" ip saddr %s udp dport %d accept\n", vHost, appIP, dnsPort))
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" ip saddr %s tcp dport %d accept\n", vHost, appIP, dnsPort))
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" drop\n", vHost))
	sb.WriteString("    }\n\n")

	// FORWARD: Zero-Forwarding, Zero-NAT policy. DROP all packets from veth-tux trying to reach WAN
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority filter; policy drop;\n")
	sb.WriteString(fmt.Sprintf("        iifname \"%s\" drop\n", vHost))
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

// applyNFTRules feeds ruleset into nft -f - pipe atomically
func (e *NetNSEngine) applyNFTRules(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft error: %s (%w)", string(out), err)
	}
	return nil
}

// ExecCommand builds the command to execute a binary inside the isolated namespace with privilege drop
func (e *NetNSEngine) ExecCommand(binary string, args []string, env []string) *exec.Cmd {
	nsName := e.NetNSName()

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "netns", "exec", nsName)

	// If root and TargetUser is set, drop privileges via runuser
	if os.Geteuid() == 0 && e.cfg.TargetUser != "" && e.cfg.TargetUser != "root" {
		cmdArgs = append(cmdArgs, "runuser", "-u", e.cfg.TargetUser, "--", binary)
	} else {
		cmdArgs = append(cmdArgs, binary)
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("ip", cmdArgs...)

	// Clean proxy environment pointing to the Tor gateway
	socksH := fmt.Sprintf("socks5h://%s:%d", e.GatewayIP(), e.cfg.TorSocksPort)
	cleanEnv := []string{
		fmt.Sprintf("ALL_PROXY=%s", socksH),
		fmt.Sprintf("all_proxy=%s", socksH),
		fmt.Sprintf("HTTP_PROXY=%s", socksH),
		fmt.Sprintf("http_proxy=%s", socksH),
		fmt.Sprintf("HTTPS_PROXY=%s", socksH),
		fmt.Sprintf("https_proxy=%s", socksH),
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
		"TUXPROXY_ACTIVE=1",
		"TUXPROXY_MODE=netns",
	}

	for _, e := range env {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "all_proxy=") ||
			strings.HasPrefix(lower, "http_proxy=") ||
			strings.HasPrefix(lower, "https_proxy=") {
			continue
		}
		cleanEnv = append(cleanEnv, e)
	}
	cmd.Env = cleanEnv

	return cmd
}

// Teardown tears down the namespace, interfaces, firewall rules, and metadata
func (e *NetNSEngine) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.teardownInternal()
}

func (e *NetNSEngine) teardownInternal() error {
	var errs []string

	// 1. Delete nftables table
	if out, err := e.runner("nft", "delete", "table", "inet", e.NFTTable()); err != nil {
		// Ignore if table does not exist
		if !strings.Contains(string(out), "No such file or directory") {
			errs = append(errs, fmt.Sprintf("nft delete failed: %s", string(out)))
		}
	}

	// 2. Delete veth interface (deleting host end automatically deletes app end)
	if out, err := e.runner("ip", "link", "del", e.VethHost()); err != nil {
		if !strings.Contains(string(out), "Cannot find device") {
			errs = append(errs, fmt.Sprintf("ip link del failed: %s", string(out)))
		}
	}

	// 3. Delete Network Namespace
	if out, err := e.runner("ip", "netns", "del", e.NetNSName()); err != nil {
		if !strings.Contains(string(out), "No such file or directory") {
			errs = append(errs, fmt.Sprintf("ip netns del failed: %s", string(out)))
		}
	}

	// 4. Remove /etc/netns directory
	_ = os.RemoveAll(e.ResolvConfDir())

	// 5. Remove metadata file
	if e.metaPath != "" {
		_ = os.Remove(e.metaPath)
	}

	e.active = false

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// recordMetadata writes session details and process starttime to disk for GC
func (e *NetNSEngine) recordMetadata() error {
	metaDir := getSessionMetaDir()
	if err := os.MkdirAll(metaDir, 0700); err != nil {
		return err
	}

	pid := os.Getpid()
	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		return fmt.Errorf("failed to get starttime for PID %d: %w", pid, err)
	}

	meta := SessionMetadata{
		SessionID:     e.cfg.SessionID,
		SubnetID:      e.cfg.SubnetID,
		PID:           pid,
		StartTime:     startTime,
		NetNSName:     e.NetNSName(),
		VethHost:      e.VethHost(),
		VethApp:       e.VethApp(),
		ResolvConfDir: e.ResolvConfDir(),
		NFTTable:      e.NFTTable(),
		CreatedAt:     time.Now().UTC(),
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	e.metaPath = filepath.Join(metaDir, fmt.Sprintf("session-%s.json", e.cfg.SessionID))
	return os.WriteFile(e.metaPath, data, 0600)
}

// GetProcessStartTime safely extracts field 22 (starttime) from /proc/<pid>/stat
// handles process names containing spaces and parentheses via strings.LastIndex
func GetProcessStartTime(pid int) (uint64, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}

	s := string(data)
	lastParen := strings.LastIndex(s, ")")
	if lastParen == -1 {
		return 0, fmt.Errorf("invalid stat format for PID %d", pid)
	}

	// Remainder begins right after the closing parenthesis:
	// Field 3 (state) is index 0
	// Field 22 (starttime) is index 19 (22 - 3 = 19)
	fields := strings.Fields(s[lastParen+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("insufficient fields in stat for PID %d", pid)
	}

	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse starttime field: %w", err)
	}

	return startTime, nil
}

// ReconcileOrphans prunes leaked netns, veth interfaces, and nftables tables from dead processes
func ReconcileOrphans(runner CommandRunner) ([]string, error) {
	if runner == nil {
		runner = defaultCommandRunner
	}

	metaDir := getSessionMetaDir()
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cleaned []string

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(metaDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var meta SessionMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		isAlive := false
		if meta.PID > 0 {
			// Verify if PID exists and starttime matches (protect against PID recycling)
			currentStartTime, err := GetProcessStartTime(meta.PID)
			if err == nil && currentStartTime == meta.StartTime {
				// Process is genuinely still alive
				isAlive = true
			}
		}

		if !isAlive {
			// Process died or PID was recycled -> clean up orphaned resources
			_, _ = runner("nft", "delete", "table", "inet", meta.NFTTable)
			_, _ = runner("ip", "link", "del", meta.VethHost)
			_, _ = runner("ip", "netns", "del", meta.NetNSName)
			_ = os.RemoveAll(meta.ResolvConfDir)
			_ = os.Remove(filePath)
			cleaned = append(cleaned, meta.SessionID)
		}
	}

	return cleaned, nil
}

func getSessionMetaDir() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		if os.Geteuid() == 0 {
			base = "/run"
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "tuxproxy", "sessions")
}
