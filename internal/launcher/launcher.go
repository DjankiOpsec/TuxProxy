package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"tuxproxy/internal/banner"
	"tuxproxy/internal/config"
	"tuxproxy/internal/leak"
	"tuxproxy/internal/tor"
)

// Options specifies launcher parameters
type Options struct {
	Command          string
	Args             []string
	ForceProxychains bool
}

// Launch executes the target application wrapped in zero-leak proxy guards
func Launch(cfg *config.Config, mgr *tor.Manager, opt Options) error {
	targetBin, err := exec.LookPath(opt.Command)
	if err != nil {
		return fmt.Errorf("command not found in PATH: %s", opt.Command)
	}

	socksPort, httpPort, _, _ := mgr.Ports()
	mode := strings.ToLower(strings.TrimSpace(cfg.UniversalAppMode))
	useProxychains := opt.ForceProxychains || cfg.ForceProxychains || mode == "proxychains"
	forceElectron := mode == "electron"

	var cmd *exec.Cmd

	if useProxychains {
		proxychainsBin := cfg.ProxychainsPath
		if proxychainsBin == "" {
			proxychainsBin = "proxychains4"
		}

		if _, err := exec.LookPath(proxychainsBin); err != nil {
			fmt.Printf("%s Внимание: бинарник %s не найден в системе. Переключение на стандартную инжекцию переменных окружения.\n",
				banner.TagWarn("ПРЕДУПРЕЖДЕНИЕ"), proxychainsBin)
			useProxychains = false
		} else {
			confPath, err := leak.GenerateProxychainsConfig(os.TempDir(), socksPort)
			if err != nil {
				return fmt.Errorf("ошибка генерации конфигурации proxychains: %w", err)
			}
			defer os.Remove(confPath)

			pcArgs := append([]string{"-q", "-f", confPath, targetBin}, opt.Args...)
			cmd = exec.Command(proxychainsBin, pcArgs...)
			fmt.Printf("%s Универсальный перехват сокетов libc через %s (LD_PRELOAD для любых ELF-бинарников)\n",
				banner.TagSecure("ИЗОЛЯЦИЯ"), proxychainsBin)
		}
	}

	if !useProxychains {
		binLower := strings.ToLower(targetBin)
		if forceElectron || leak.IsChromiumOrElectron(targetBin) {
			// Среда Electron / Chromium (antigravity-ide, VS Code, Chrome, Brave, Discord и т.д.)
			flags := leak.ChromiumFlags(socksPort, cfg.PreventWebRTCLeak, cfg.PreventDNSLeak)
			allArgs := append(flags, opt.Args...)
			cmd = exec.Command(targetBin, allArgs...)
			fmt.Printf("%s Среда Electron/Chromium :: Применены флаги изоляции WebRTC, DNS-маршрутизации и хост-резолвера\n",
				banner.TagSecure("ПЕСОЧНИЦА"))
		} else if strings.Contains(binLower, "java") || strings.Contains(binLower, "idea") || strings.Contains(binLower, "pycharm") || strings.Contains(binLower, "android-studio") {
			cmd = exec.Command(targetBin, opt.Args...)
			fmt.Printf("%s Среда Java/JVM :: Применены системные параметры _JAVA_OPTIONS для прямого туннелирования SOCKS5h/HTTP\n",
				banner.TagSecure("ПЕСОЧНИЦА"))
		} else {
			// Универсальный исполняемый файл (CLI, скрипты, сервисы, утилиты)
			cmd = exec.Command(targetBin, opt.Args...)
			fmt.Printf("%s Универсальный процесс :: Применено защищенное окружение (ALL_PROXY=socks5h, HTTP_PROXY)\n",
				banner.TagSecure("ОКРУЖЕНИЕ"))
		}
	}

	// Инжекция защищенных переменных сетевого окружения (ALL_PROXY=socks5h://, HTTP_PROXY и др.)
	cmd.Env = leak.BuildEnvironment(socksPort, httpPort)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("сбой запуска целевого процесса: %w", err)
	}

	fmt.Printf("%s Процесс успешно запущен: %s%s%s (PID: %d)\n\n",
		banner.TagOK("СТАТУС"), banner.Bold, opt.Command, banner.Reset, cmd.Process.Pid)

	// Перенаправление системных сигналов в дочерний процесс
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmd.Wait()
	}()

	select {
	case sig := <-sigChan:
		fmt.Printf("\n%s Получен сигнал %v, передача в целевой процесс...\n", banner.TagWarn("СИГНАЛ"), sig)
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
		// Wait for process to exit
		select {
		case err := <-doneChan:
			return err
		}
	case err := <-doneChan:
		return err
	}
}
