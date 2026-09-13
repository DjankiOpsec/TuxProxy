package shell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"tuxproxy/internal/config"
	"tuxproxy/internal/leak"
	"tuxproxy/internal/tor"
)

const (
	hookStartMarker = "# >>> TuxProxy Shell Integration >>>"
	hookEndMarker   = "# <<< TuxProxy Shell Integration <<<"
)

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

// IsHookInstalled проверяет, установлен ли хук в файлах конфигурации оболочки
func IsHookInstalled() bool {
	files := getShellConfigFiles()
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

// InstallHook добавляет интеграционный блок в ~/.bashrc и ~/.zshrc
func InstallHook() error {
	files := getShellConfigFiles()
	if len(files) == 0 {
		home, _ := os.UserHomeDir()
		files = []string{filepath.Join(home, ".bashrc")}
	}

	hookBlock := fmt.Sprintf("\n%s\nif command -v tuxproxy >/dev/null 2>&1; then\n    eval \"$(tuxproxy hook init 2>/dev/null)\"\nfi\n%s\n",
		hookStartMarker, hookEndMarker)

	for _, file := range files {
		content := ""
		if data, err := os.ReadFile(file); err == nil {
			content = string(data)
			if strings.Contains(content, hookStartMarker) {
				continue // Уже установлен
			}
		}

		newContent := strings.TrimRight(content, "\n") + "\n" + hookBlock
		if err := os.WriteFile(file, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("не удалось записать в %s: %w", file, err)
		}
	}
	return nil
}

// RemoveHook удаляет интеграционный блок из ~/.bashrc и ~/.zshrc
func RemoveHook() error {
	files := getShellConfigFiles()
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		content := string(data)
		startIdx := strings.Index(content, hookStartMarker)
		endIdx := strings.Index(content, hookEndMarker)

		if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
			endIdx += len(hookEndMarker)
			cleaned := content[:startIdx] + content[endIdx:]
			cleaned = strings.TrimRight(cleaned, "\n") + "\n"
			_ = os.WriteFile(file, []byte(cleaned), 0644)
		}
	}
	return nil
}

// InitScript генерирует Bash/Zsh код для автоподключения к терминалу
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

	// Автозапуск демона Tor в фоне, если порт не слушается
	if cfg.TerminalAutoStartDaemon {
		sb.WriteString(fmt.Sprintf(`if ! ss -tuln 2>/dev/null | grep -q ":%d " && ! pgrep -f "tuxproxy daemon" >/dev/null 2>&1; then
    tuxproxy daemon >/dev/null 2>&1 &
    disown
fi
`, socksPort))
	}

	// Экспорт переменных окружения (socks5h обеспечивает удаленный DNS и поддержку как HTTP, так и HTTPS)
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

	// Динамический индикатор в строке приглашения терминала (отображается ТОЛЬКО если прокси активен)
	if cfg.ShowPromptIndicator {
		sb.WriteString(fmt.Sprintf(`if [ -n "$ZSH_VERSION" ]; then
    setopt prompt_subst 2>/dev/null
    __tuxproxy_indicator() {
        if [ "$TUXPROXY_ACTIVE" = "1" ] && [ -n "$ALL_PROXY" ]; then
            echo -ne "%%F{cyan}[tuxproxy:${TUXPROXY_COUNTRY:-%s}]%%f "
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

	// Вспомогательные функции для терминала
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

// EnvExport выводит чистые команды export или unset для текущего шелла
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

// SpawnSubshell запускает интерактивный изолированный дочерний шелл
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

	// Установка индикатора в зависимости от типа командной оболочки
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
