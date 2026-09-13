package shell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"tuxproxy/internal/config"
	"tuxproxy/internal/leak"
	"tuxproxy/internal/tor"
)

const (
	hookStartMarker = "# >>> TuxProxy Shell Integration >>>"
	hookEndMarker   = "# <<< TuxProxy Shell Integration <<<"
	maxBackups      = 3
)

const nonInteractiveGuard = `case "$-" in
    *i*) ;;
      *) return 0 2>/dev/null || exit 0 ;;
esac
[ -z "$PS1" ] && return 0 2>/dev/null`

func getLockFilePath() string {
	if p := os.Getenv("TUXPROXY_LOCK_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".tuxproxy.lock")
	}
	return filepath.Join(home, ".tuxproxy.lock")
}

func withShellLock(fn func() error) error {
	lockPath := getLockFilePath()
	lockDir := filepath.Dir(lockPath)
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return fmt.Errorf("failed to create lock directory %s: %w", lockDir, err)
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire flock on %s: %w", lockPath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

func atomicWriteFileWithFsync(targetPath string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create temp file in same directory: base.tmp.<random>
	tmpFile, err := os.CreateTemp(dir, fmt.Sprintf("%s.tmp.", base))
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()

	var renamed bool
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write to temp file %s: %w", tmpPath, err)
	}

	// 1. file.Sync() flush buffers
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync temp file %s: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file %s: %w", tmpPath, err)
	}

	// 2. os.Chmod preserving original permissions
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to chmod temp file %s: %w", tmpPath, err)
	}

	// 3. os.Rename (atomic replacement on same filesystem)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpPath, targetPath, err)
	}
	renamed = true

	// 4. dir.Sync() on parent directory
	dirFile, err := os.Open(dir)
	if err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}

func createBackupWithRetention(targetPath string) error {
	info, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		return fmt.Errorf("failed to read %s for backup: %w", targetPath, err)
	}

	ts := time.Now().UTC().Format("20060102150405.000000000")
	backupPath := fmt.Sprintf("%s.tuxproxy.bak.%s", targetPath, ts)

	if err := atomicWriteFileWithFsync(backupPath, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to create backup %s: %w", backupPath, err)
	}

	return pruneOldBackups(targetPath, maxBackups)
}

func pruneOldBackups(targetPath string, keep int) error {
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	prefix := fmt.Sprintf("%s.tuxproxy.bak.", base)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			backups = append(backups, entry.Name())
		}
	}

	sort.Strings(backups)

	if len(backups) > keep {
		toRemove := len(backups) - keep
		for i := 0; i < toRemove; i++ {
			p := filepath.Join(dir, backups[i])
			_ = os.Remove(p)
		}
	}
	return nil
}

// ListBackups returns all existing backup file paths for targetPath, sorted newest first
func ListBackups(targetPath string) ([]string, error) {
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	prefix := fmt.Sprintf("%s.tuxproxy.bak.", base)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			backups = append(backups, entry.Name())
		}
	}
	sort.Strings(backups)

	var fullPaths []string
	for i := len(backups) - 1; i >= 0; i-- {
		fullPaths = append(fullPaths, filepath.Join(dir, backups[i]))
	}
	return fullPaths, nil
}

// RestoreLatestBackup restores targetPath from its newest backup file
func RestoreLatestBackup(targetPath string) error {
	return withShellLock(func() error {
		backups, err := ListBackups(targetPath)
		if err != nil {
			return err
		}
		if len(backups) == 0 {
			return fmt.Errorf("no backups found for %s", targetPath)
		}

		latestBackup := backups[0]
		data, err := os.ReadFile(latestBackup)
		if err != nil {
			return fmt.Errorf("failed to read backup %s: %w", latestBackup, err)
		}

		perm := os.FileMode(0644)
		if info, err := os.Stat(latestBackup); err == nil {
			perm = info.Mode().Perm()
		}

		return atomicWriteFileWithFsync(targetPath, data, perm)
	})
}

func generateHookBlock() string {
	return fmt.Sprintf("%s\n%s\n\nif command -v tuxproxy >/dev/null 2>&1; then\n    eval \"$(tuxproxy hook init 2>/dev/null)\"\nfi\n%s",
		hookStartMarker,
		nonInteractiveGuard,
		hookEndMarker,
	)
}

func injectOrUpdateHook(content string) (string, bool) {
	hookBlock := generateHookBlock()
	startIdx := strings.Index(content, hookStartMarker)
	endIdx := strings.Index(content, hookEndMarker)

	if startIdx != -1 && endIdx != -1 && endIdx >= startIdx {
		fullEndIdx := endIdx + len(hookEndMarker)
		existingBlock := content[startIdx:fullEndIdx]
		if existingBlock == hookBlock {
			return content, false // Already up to date
		}
		newContent := content[:startIdx] + hookBlock + content[fullEndIdx:]
		return newContent, true
	}

	trimmed := strings.TrimRight(content, "\n")
	var newContent string
	if trimmed == "" {
		newContent = hookBlock + "\n"
	} else {
		newContent = trimmed + "\n\n" + hookBlock + "\n"
	}
	return newContent, true
}

func stripHook(content string) (string, bool) {
	startIdx := strings.Index(content, hookStartMarker)
	endIdx := strings.Index(content, hookEndMarker)

	if startIdx == -1 || endIdx == -1 || endIdx < startIdx {
		return content, false // Hook not present
	}

	fullEndIdx := endIdx + len(hookEndMarker)
	if fullEndIdx < len(content) && content[fullEndIdx] == '\n' {
		fullEndIdx++
	}

	before := content[:startIdx]
	after := content[fullEndIdx:]

	trimmedBefore := strings.TrimRight(before, "\n")
	trimmedAfter := strings.TrimLeft(after, "\n")

	var result string
	if trimmedBefore == "" {
		if trimmedAfter == "" {
			result = ""
		} else {
			result = trimmedAfter + "\n"
		}
	} else {
		if trimmedAfter == "" {
			result = trimmedBefore + "\n"
		} else {
			result = trimmedBefore + "\n\n" + trimmedAfter + "\n"
		}
	}

	return result, true
}

// target RC files to hook
func getShellConfigFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	}

	var existing []string
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	return existing
}

// IsHookInstalled checks if hook is installed in shell configuration files
func IsHookInstalled() bool {
	files := getShellConfigFiles()
	return IsHookInstalledInFiles(files)
}

// IsHookInstalledInFiles checks if hook is installed in the given list of files
func IsHookInstalledInFiles(files []string) bool {
	if len(files) == 0 {
		return false
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err == nil && strings.Contains(string(data), hookStartMarker) {
			return true
		}
	}
	return false
}

func installHookToFile(file string) error {
	perm := os.FileMode(0644)
	var content string

	if data, err := os.ReadFile(file); err == nil {
		content = string(data)
		if info, statErr := os.Stat(file); statErr == nil {
			perm = info.Mode().Perm()
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", file, err)
	}

	newContent, changed := injectOrUpdateHook(content)
	if !changed {
		return nil // Idempotent: already installed and identical
	}

	// Backup before modifying existing file
	if _, err := os.Stat(file); err == nil {
		if err := createBackupWithRetention(file); err != nil {
			return fmt.Errorf("failed to create backup for %s: %w", file, err)
		}
	}

	return atomicWriteFileWithFsync(file, []byte(newContent), perm)
}

func removeHookFromFile(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", file, err)
	}

	content := string(data)
	cleaned, changed := stripHook(content)
	if !changed {
		return nil // Not installed
	}

	perm := os.FileMode(0644)
	if info, statErr := os.Stat(file); statErr == nil {
		perm = info.Mode().Perm()
	}

	// Backup before removing hook from existing file
	if err := createBackupWithRetention(file); err != nil {
		return fmt.Errorf("failed to create backup for %s: %w", file, err)
	}

	return atomicWriteFileWithFsync(file, []byte(cleaned), perm)
}

// InstallHookFiles installs TuxProxy integration into the specified config files
func InstallHookFiles(files []string) error {
	return withShellLock(func() error {
		for _, file := range files {
			if err := installHookToFile(file); err != nil {
				return err
			}
		}
		return nil
	})
}

// InstallHook adds integration block into ~/.bashrc and ~/.zshrc
func InstallHook() error {
	files := getShellConfigFiles()
	if len(files) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to determine user home directory: %w", err)
		}
		files = []string{filepath.Join(home, ".bashrc")}
	}
	return InstallHookFiles(files)
}

// RemoveHookFiles removes TuxProxy integration from specified config files
func RemoveHookFiles(files []string) error {
	return withShellLock(func() error {
		for _, file := range files {
			if err := removeHookFromFile(file); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveHook removes integration block from ~/.bashrc and ~/.zshrc
func RemoveHook() error {
	files := getShellConfigFiles()
	return RemoveHookFiles(files)
}

// UninstallHook is an alias for RemoveHook
func UninstallHook() error {
	return RemoveHook()
}

// UninstallHookFiles is an alias for RemoveHookFiles
func UninstallHookFiles(files []string) error {
	return RemoveHookFiles(files)
}

// InitScript generates Bash/Zsh code for terminal autoconfiguration
func InitScript(cfg *config.Config) string {
	socksPort := cfg.SocksPort
	httpPort := cfg.HTTPPort
	country := strings.ToUpper(cfg.ExitCountry)
	if country == "" || country == "ANY" {
		country = "TOR"
	}

	socksH := fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)

	var sb strings.Builder
	sb.WriteString("# Сгенерировано TuxProxy для интеграции с сессией терминала\n")
	sb.WriteString(nonInteractiveGuard)
	sb.WriteString("\n\n")

	// Auto-start daemon in background if port is not yet listening
	if cfg.TerminalAutoStartDaemon {
		sb.WriteString(fmt.Sprintf(`if ! ss -tuln 2>/dev/null | grep -q ":%d " && ! pgrep -f "tuxproxy daemon" >/dev/null 2>&1; then
    tuxproxy daemon >/dev/null 2>&1 &
    disown
fi
`, socksPort))
	}

	// Export proxy environment variables
	sb.WriteString(fmt.Sprintf("export ALL_PROXY=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export all_proxy=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export HTTP_PROXY=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export http_proxy=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export HTTPS_PROXY=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export https_proxy=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export FTP_PROXY=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export ftp_proxy=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export SOCKS_PROXY=\"%s\"\n", socksH))
	sb.WriteString(fmt.Sprintf("export socks_proxy=\"%s\"\n", socksH))
	sb.WriteString("export NO_PROXY=\"localhost,127.0.0.1\"\n")
	sb.WriteString("export no_proxy=\"localhost,127.0.0.1\"\n")
	sb.WriteString("export TUXPROXY_ACTIVE=1\n")
	sb.WriteString(fmt.Sprintf("export TUXPROXY_COUNTRY=\"%s\"\n", country))

	if cfg.JavaProxySupport {
		sb.WriteString(fmt.Sprintf("export _JAVA_OPTIONS=\"-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d\"\n",
			socksPort, httpPort))
		sb.WriteString(fmt.Sprintf("export JAVA_TOOL_OPTIONS=\"-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d\"\n",
			socksPort, httpPort))
	}

	// Dynamic prompt indicator
	if cfg.ShowPromptIndicator {
		sb.WriteString(fmt.Sprintf(`if [ -n "$ZSH_VERSION" ]; then
    setopt prompt_subst 2>/dev/null
    __tuxproxy_indicator() {
        if [ "$TUXPROXY_ACTIVE" = "1" ] && [ -n "$ALL_PROXY" ]; then
            echo -ne "%%%%F{cyan}[tuxproxy:${TUXPROXY_COUNTRY:-%s}]%%%%f "
        fi
    }
    if [[ "$PROMPT" != *'$(__tuxproxy_indicator)'* ]]; then
        PROMPT='$(__tuxproxy_indicator)'"$PROMPT"
    fi
else
    __tuxproxy_indicator() {
        if [ "$TUXPROXY_ACTIVE" = "1" ] && [ -n "$ALL_PROXY" ]; then
            echo -ne "\\[\\033[1;36m\\][tuxproxy:${TUXPROXY_COUNTRY:-%s}]\\[\\033[0m\\] "
        fi
    }
    if [[ "$PS1" != *'$(__tuxproxy_indicator)'* ]]; then
        PS1='$(__tuxproxy_indicator)'"$PS1"
    fi
fi
`, country, country))
	}

	// Helper terminal functions
	sb.WriteString(fmt.Sprintf(`
tuxoff() {
    unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy FTP_PROXY ftp_proxy SOCKS_PROXY socks_proxy _JAVA_OPTIONS JAVA_TOOL_OPTIONS
    export TUXPROXY_ACTIVE=0
    echo "[*] TuxProxy: Проксирование текущего терминала ОТКЛЮЧЕНО."
}

tuxon() {
    eval "$(tuxproxy env)"
    export TUXPROXY_ACTIVE=1
    echo "[+] TuxProxy: Проксирование текущего терминала ВКЛЮЧЕНО."
}

tuxip() {
    if ! ss -tuln 2>/dev/null | grep -q ":%d "; then
        echo "[-] Служба Tor не запущена на порту %d."
        return 1
    fi
    curl -s --socks5-hostname 127.0.0.1:%d https://check.torproject.org/api/ip 2>/dev/null || \
    curl -s --socks5-hostname 127.0.0.1:%d https://icanhazip.com 2>/dev/null || \
    echo "[-] Ошибка проверки внешнего адреса через SOCKS5h."
}
`, socksPort, socksPort, socksPort, socksPort))

	return sb.String()
}

// EnvExport generates clean export or unset commands for shell
func EnvExport(cfg *config.Config, disable bool) string {
	if disable {
		return "unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy FTP_PROXY ftp_proxy SOCKS_PROXY socks_proxy _JAVA_OPTIONS JAVA_TOOL_OPTIONS\nexport TUXPROXY_ACTIVE=0\n"
	}

	socksPort := cfg.SocksPort
	httpPort := cfg.HTTPPort
	socksH := fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)
	country := strings.ToUpper(cfg.ExitCountry)
	if country == "" || country == "ANY" {
		country = "TOR"
	}

	return fmt.Sprintf(`export ALL_PROXY="%s"
export all_proxy="%s"
export HTTP_PROXY="%s"
export http_proxy="%s"
export HTTPS_PROXY="%s"
export https_proxy="%s"
export FTP_PROXY="%s"
export ftp_proxy="%s"
export SOCKS_PROXY="%s"
export socks_proxy="%s"
export NO_PROXY="localhost,127.0.0.1"
export no_proxy="localhost,127.0.0.1"
export TUXPROXY_ACTIVE=1
export TUXPROXY_COUNTRY="%s"
export _JAVA_OPTIONS="-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d"
export JAVA_TOOL_OPTIONS="-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d"
`, socksH, socksH, socksH, socksH, socksH, socksH, socksH, socksH, socksH, socksH, country, socksPort, httpPort, socksPort, httpPort)
}

// SpawnSubshell spawns an interactive isolated subshell
func SpawnSubshell(cfg *config.Config, mgr *tor.Manager) error {
	userShell := os.Getenv("SHELL")
	if userShell == "" {
		userShell = "/bin/bash"
	}

	socksPort, httpPort, _, _ := mgr.Ports()
	env := leak.BuildEnvironment(socksPort, httpPort)

	country := strings.ToUpper(cfg.ExitCountry)
	if country == "" || country == "ANY" {
		country = "TOR"
	}

	env = append(env, fmt.Sprintf("TUXPROXY_COUNTRY=%s", country))
	env = append(env, "TUXPROXY_ACTIVE=1")

	if strings.Contains(userShell, "zsh") {
		currentPrompt := os.Getenv("PROMPT")
		if currentPrompt == "" {
			currentPrompt = "%F{blue}➜%f "
		}
		env = append(env, fmt.Sprintf("PROMPT=%%F{cyan}[tuxproxy:%s]%%f %s", country, currentPrompt))
	} else {
		currentPS1 := os.Getenv("PS1")
		if currentPS1 == "" {
			currentPS1 = "\\u@\\h:\\w\\$ "
		}
		env = append(env, fmt.Sprintf("PS1=\\[\\033[1;36m\\][tuxproxy:%s]\\[\\033[0m\\] %s", country, currentPS1))
	}

	cmd := exec.Command(userShell, "-i")
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
