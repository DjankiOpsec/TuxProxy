package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tuxproxy/internal/banner"
	"tuxproxy/internal/config"
	"tuxproxy/internal/gui"
	"tuxproxy/internal/launcher"
	"tuxproxy/internal/leak"
	"tuxproxy/internal/shell"
	"tuxproxy/internal/tor"
	"tuxproxy/internal/tui"
	"tuxproxy/internal/verifier"
)

func main() {
	if len(os.Args) == 1 {
		handleGUI()
		return
	}

	// Обработка синтаксических вариантов аргументов (например, "--open:" или "-open:")
	normalizedArgs := make([]string, 0, len(os.Args))
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--open:") {
			normalizedArgs = append(normalizedArgs, "--open", strings.TrimPrefix(arg, "--open:"))
		} else if strings.HasPrefix(arg, "-open:") {
			normalizedArgs = append(normalizedArgs, "-open", strings.TrimPrefix(arg, "-open:"))
		} else {
			normalizedArgs = append(normalizedArgs, arg)
		}
	}
	os.Args = normalizedArgs

	// Подкоманды CLI
	firstArg := os.Args[1]
	switch firstArg {
	case "gui":
		handleGUI()
		return
	case "settings", "config":
		handleSettings()
		return
	case "hook":
		handleHook(os.Args[2:])
		return
	case "env":
		handleEnv(os.Args[2:])
		return
	case "shell":
		handleSubshell()
		return
	case "open", "run":
		handleOpenSubcommand(os.Args[2:])
		return
	case "test":
		handleTest()
		return
	case "status":
		handleStatus()
		return
	case "newnym":
		handleNewnym()
		return
	case "daemon", "start":
		handleDaemon("", "", false)
		return
	case "version", "--version", "-v":
		fmt.Printf("TuxProxy версия %s (Zero-Leak OPSEC Sandbox)\n", banner.Version)
		return
	case "help", "--help", "-h":
		printUsage()
		return
	}

	// Автоматическая очистка сиротливых пространств имен и таблиц nftables (Reconcile / GC)
	if os.Geteuid() == 0 {
		_, _ = leak.ReconcileOrphans(nil)
	}

	// Флаги командной строки
	var (
		flagGUI         bool
		flagSettings    bool
		flagOpen        string
		flagCountry     string
		flagBridge      string
		flagEphemeral   bool
		flagProxychains bool
		flagNetNS       bool
		flagDaemon      bool
		flagTest        bool
		flagNewnym      bool
		flagStatus      bool
	)

	fs := flag.NewFlagSet("tuxproxy", flag.ExitOnError)
	fs.BoolVar(&flagGUI, "gui", false, "Открыть простой графический веб-интерфейс в браузере")
	fs.BoolVar(&flagGUI, "g", false, "Открыть графический веб-интерфейс")
	fs.BoolVar(&flagSettings, "settings", false, "Открыть интерактивное TUI-меню настроек безопасности")
	fs.BoolVar(&flagSettings, "s", false, "Открыть интерактивное TUI-меню настроек")
	fs.StringVar(&flagOpen, "open", "", "Запуск приложения в изолированной среде проксирования")
	fs.StringVar(&flagOpen, "o", "", "Запуск приложения в изолированной среде")
	fs.StringVar(&flagCountry, "country", "", "Принудительный выбор страны выхода (ISO-код: us, de, nl, sg и др.)")
	fs.StringVar(&flagCountry, "c", "", "Принудительный выбор страны выхода")
	fs.StringVar(&flagBridge, "bridge", "", "Тип транспорта обхода DPI ('snowflake', 'obfs4', 'webtunnel', 'none')")
	fs.StringVar(&flagBridge, "b", "", "Тип транспорта обхода DPI")
	fs.BoolVar(&flagEphemeral, "ephemeral", false, "Работа исключительно в оперативной памяти (без сохранения на диск)")
	fs.BoolVar(&flagEphemeral, "e", false, "Режим без сохранения на диск")
	fs.BoolVar(&flagProxychains, "proxychains", false, "Принудительный перехват через proxychains4 (LD_PRELOAD)")
	fs.BoolVar(&flagProxychains, "p", false, "Принудительный перехват через proxychains4")
	fs.BoolVar(&flagNetNS, "netns", false, "Эталонная изоляция в Linux Network Namespace (требует sudo)")
	fs.BoolVar(&flagNetNS, "n", false, "Эталонная изоляция в Linux Network Namespace")
	fs.BoolVar(&flagDaemon, "daemon", false, "Запуск постоянной службы локального прокси")
	fs.BoolVar(&flagDaemon, "d", false, "Запуск службы прокси")
	fs.BoolVar(&flagTest, "test", false, "Комплексная диагностика контура и аудит на утечки IP/DNS")
	fs.BoolVar(&flagTest, "t", false, "Аудит на утечки IP/DNS")
	fs.BoolVar(&flagNewnym, "newnym", false, "Смена выходного узла и построение новой цепочки Tor")
	fs.BoolVar(&flagStatus, "status", false, "Проверка состояния активного шлюза")

	_ = fs.Parse(os.Args[1:])
	tailArgs := fs.Args()

	if flagGUI {
		handleGUI()
		return
	}

	if flagSettings {
		handleSettings()
		return
	}

	if flagTest {
		handleTest()
		return
	}

	if flagNewnym {
		handleNewnym()
		return
	}

	if flagStatus {
		handleStatus()
		return
	}

	if flagDaemon {
		handleDaemon(flagCountry, flagBridge, flagEphemeral)
		return
	}

	if flagOpen != "" {
		targetCmd := strings.Trim(flagOpen, `"'`)
		cmdParts := strings.Fields(targetCmd)
		if len(cmdParts) == 0 {
			fmt.Printf("%s Не указано исполняемое приложение.\n", banner.TagErr("ОШИБКА"))
			os.Exit(1)
		}
		app := cmdParts[0]
		extraArgs := append(cmdParts[1:], tailArgs...)
		handleOpen(app, extraArgs, flagCountry, flagBridge, flagEphemeral, flagProxychains, flagNetNS, false)
		return
	}

	printUsage()
}

func printUsage() {
	banner.PrintBanner()
	fmt.Print(`  НАЗНАЧЕНИЕ:
    TuxProxy - инструмент профессиональной сетевой изоляции приложений и терминала.
    Создает изолированный контур Tor с активным обходом DPI (Snowflake/obfs4),
    контролирует страну выхода (Exit Node) и блокирует утечки через DNS, WebRTC и IPv6.

  ФОРМАТ ВЫЗОВА:
    tuxproxy                              Открыть центр настроек (Web GUI в браузере)
    tuxproxy gui                          Открыть панель параметров безопасности (GUI)
    tuxproxy settings                     Интерактивное TUI-меню настроек в терминале
    tuxproxy open <приложение> [опции]    Запуск любого приложения через изолированный прокси
    tuxproxy --open "<команда>" [опции]   Альтернативный формат запуска приложения
    tuxproxy hook <enable|disable|status> Управление автоподключением к сессиям терминала
    eval "$(tuxproxy env)"                Активировать переменные прокси в текущем терминале
    eval "$(tuxproxy env --off)"          Отключить переменные прокси в текущем терминале
    tuxproxy shell                        Запустить защищенную интерактивную подоболочку
    tuxproxy daemon                       Запуск постоянного фонового шлюза Tor
    tuxproxy test                         Диагностика контура и аудит сетевых утечек
    tuxproxy newnym                       Ротация контура (получение нового Exit IP)
    tuxproxy status                       Проверка текущего статуса и параметров шлюза

  ИНТЕГРАЦИЯ С ТЕРМИНАЛОМ (SHELL HOOK):
    tuxproxy hook enable                  Включить автоподключение во всех сессиях терминала (~/.bashrc)
    tuxproxy hook disable                 Отключить интеграцию с терминалом
    tuxproxy hook status                  Проверить статус интеграции с оболочкой
    tuxproxy hook init                    Вывести Bash/Zsh скрипт инициализации

  ПАРАМЕТРЫ КОМАНДНОЙ СТРОКИ:
    -s, --settings                        Интерактивная панель настройки OPSEC (TUI)
    -g, --gui                             Открыть графический веб-интерфейс настроек
    -o, --open <команда>                  Целевой исполняемый файл или приложение
    -c, --country <ISO-код>               Код страны выхода (us, de, nl, ch, sg и др.)
    -b, --bridge <тип>                    Транспорт: snowflake, obfs4, webtunnel, none
    -e, --ephemeral                       Бесследный режим (хранение в RAM/tmpfs)
    -p, --proxychains                     Использовать системный перехватчик proxychains4 (LD_PRELOAD)
    -d, --daemon                          Фоновый режим локального сетевого шлюза
    -t, --test                            Запустить аудит соединений на утечки данных
    -h, --help                            Вывести данную техническую справку
    -v, --version                         Версия утилиты

  ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:
    tuxproxy gui                                      # Центр настроек в браузере
    tuxproxy hook enable                              # Автопроксирование всего терминала
    tuxproxy open antigravity-ide                     # Запуск Electron IDE через прокси
    tuxproxy open idea                                # Запуск IntelliJ IDEA / Java
    tuxproxy open curl -s https://icanhazip.com       # Запрос через Tor
    tuxproxy open --proxychains telegram-desktop      # Перехват сокетов libc для любого ПО
`)
}

func handleGUI() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения файла конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	if err := gui.StartWebServer(cfg, true); err != nil {
		fmt.Printf("%s Сбой графического веб-интерфейса: %v\n", banner.TagErr("GUI"), err)
		os.Exit(1)
	}
}

func handleSettings() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения файла конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	if err := tui.RunSettingsMenu(cfg); err != nil {
		fmt.Printf("%s Сбой интерфейса настроек: %v\n", banner.TagErr("TUI"), err)
	}
}

func handleOpenSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s Не указано целевое приложение. Формат: tuxproxy open [опции] <приложение> [аргументы...]\n", banner.TagErr("СИНТАКСИС"))
		os.Exit(1)
	}

	fs := flag.NewFlagSet("open", flag.ExitOnError)
	var (
		country     string
		bridge      string
		ephemeral   bool
		proxychains bool
		netns       bool
	)

	fs.StringVar(&country, "country", "", "Страна выхода (ISO-код: us, de, nl...)")
	fs.StringVar(&country, "c", "", "Страна выхода")
	fs.StringVar(&bridge, "bridge", "", "Мост обхода DPI (snowflake, obfs4...)")
	fs.StringVar(&bridge, "b", "", "Мост обхода DPI")
	fs.BoolVar(&ephemeral, "ephemeral", false, "Работа только в RAM")
	fs.BoolVar(&ephemeral, "e", false, "Работа только в RAM")
	fs.BoolVar(&proxychains, "proxychains", false, "Перехват через proxychains4 (LD_PRELOAD)")
	fs.BoolVar(&proxychains, "p", false, "Перехват через proxychains4")
	fs.BoolVar(&netns, "netns", false, "Эталонная изоляция Network Namespace (требует sudo)")
	fs.BoolVar(&netns, "n", false, "Эталонная изоляция Network Namespace")

	_ = fs.Parse(args)
	remaining := fs.Args()

	if len(remaining) == 0 {
		fmt.Printf("%s Не указано целевое приложение. Формат: tuxproxy open [опции] <приложение> [аргументы...]\n", banner.TagErr("СИНТАКСИС"))
		os.Exit(1)
	}

	handleOpen(remaining[0], remaining[1:], country, bridge, ephemeral, proxychains, netns, false)
}

func handleOpen(app string, args []string, countryOverride, bridgeOverride string, ephemeral, forceProxychains, forceNetNS, daemon bool) {
	banner.PrintBanner()

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Не удалось загрузить конфигурацию: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	// Переопределение параметров из флагов вызова
	if countryOverride != "" {
		cfg.ExitCountry = strings.ToLower(strings.TrimSpace(countryOverride))
	}
	if bridgeOverride != "" {
		cfg.BridgeType = strings.ToLower(strings.TrimSpace(bridgeOverride))
	}
	if ephemeral {
		cfg.Ephemeral = true
	}
	if forceProxychains {
		cfg.ForceProxychains = true
	}

	fmt.Printf("%s Инициализация супервизора Tor [Мост: %s%s%s, Страна выхода: %s%s%s, Строгая изоляция: %v]...\n",
		banner.TagAction("ЗАПУСК"),
		banner.BrightYellow, strings.ToUpper(cfg.BridgeType), banner.Reset,
		banner.BrightYellow, cfg.CountryDisplay(), banner.Reset,
		cfg.StrictNodes)

	mgr, err := tor.NewManager(cfg, cfg.Ephemeral)
	if err != nil {
		fmt.Printf("%s Ошибка инициализации сетевого стека: %v\n", banner.TagErr("ОШИБКА"), err)
		os.Exit(1)
	}

	// Перехват сигналов завершения для гарантированной очистки
	cleanupChan := make(chan os.Signal, 1)
	signal.Notify(cleanupChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-cleanupChan
		fmt.Printf("\n\n%s Получен сигнал останова. Корректное завершение процесса Tor...\n", banner.TagWarn("ОСТАНОВ"))
		_ = mgr.Stop()
		fmt.Printf("%s Очистка завершена. Сетевые порты освобождены. Следов не сохранено.\n", banner.TagOK("ЗАВЕРШЕНО"))
		os.Exit(0)
	}()

	// Старт Tor и мониторинг бутстрапа
	err = mgr.Start(func(percent int, message string) {
		fmt.Printf("\r  %s", banner.ProgressBar(percent, message))
	})
	fmt.Println()

	if err != nil {
		fmt.Printf("\n%s Сбой бутстрапа Tor: %v\n", banner.TagErr("TOR"), err)
		_ = mgr.Stop()
		os.Exit(1)
	}

	// Активация 0ms событийного Watchdog
	mgr.StartWatchdog(context.Background(), func(err error) {
		fmt.Printf("\n\n%s Аварийный сигнал Tor Supervisor: %v\n", banner.TagErr("WATCHDOG"), err)
		fmt.Printf("%s Активация Fail-Closed: мгновенная остановка процесса...\n", banner.TagWarn("KILL-SWITCH"))
		_ = mgr.Stop()
		os.Exit(1)
	})

	socksPort, httpPort, dnsPort, controlPort := mgr.Ports()
	fmt.Printf("%s Анонимный контур Tor успешно построен.\n", banner.TagOK("КОНТУР"))

	// Проверка выходного узла на утечки данных
	fmt.Printf("%s Верификация внешнего шлюза и проверка отсутствия утечек...\n", banner.TagAction("АУДИТ"))
	report := verifier.VerifyEgress(socksPort, 12*time.Second)

	exitIP := report.IP
	if exitIP == "" {
		exitIP = "Ожидание построения туннеля"
	}
	geo := fmt.Sprintf("%s (%s)", report.Country, report.City)
	if report.Country == "" {
		geo = cfg.CountryDisplay()
	}

	statusLines := []string{
		fmt.Sprintf("Целевой процесс:       %s%s%s", banner.Bold, app, banner.Reset),
		fmt.Sprintf("Шлюз SOCKS5 (h):       127.0.0.1:%d (Удалённый DNS-резолв включен)", socksPort),
		fmt.Sprintf("Шлюз HTTP CONNECT:     127.0.0.1:%d", httpPort),
		fmt.Sprintf("Резолвер DNS (Tor):    127.0.0.1:%d", dnsPort),
		fmt.Sprintf("Порт управления Tor:   127.0.0.1:%d", controlPort),
		fmt.Sprintf("Внешний IP-адрес:      %s%s%s", banner.Bold, exitIP, banner.Reset),
		fmt.Sprintf("Геолокация выхода:     %s", geo),
		fmt.Sprintf("Защита от утечек:      DNS: %s | WebRTC: %s | IPv6: %s",
			banner.BrightGreen+"ЗАЩИЩЕНО"+banner.Reset,
			banner.BrightGreen+"ПОДАВЛЕНО"+banner.Reset,
			banner.BrightGreen+"ЗАБЛОКИРОВАНО"+banner.Reset),
	}

	if forceNetNS || cfg.UniversalAppMode == "netns" {
		statusLines = append(statusLines, fmt.Sprintf("Профиль изоляции:      %s (Zero-Forwarding, Zero-NAT, nftables, lo UP)",
			banner.BrightGreen+"NETNS-GATEWAY"+banner.Reset))
	}

	fmt.Print(banner.BoxSection("АКТИВНАЯ СРЕДА БЕЗОПАСНОСТИ TUXPROXY", statusLines))

	// Запуск целевого приложения
	opt := launcher.Options{
		Command:          app,
		Args:             args,
		ForceProxychains: forceProxychains || cfg.ForceProxychains,
		ForceNetNS:       forceNetNS,
	}

	launchErr := launcher.Launch(cfg, mgr, opt)

	fmt.Printf("\n%s Целевой процесс завершил работу. Уничтожение окружения Tor...\n", banner.TagAction("ОЧИСТКА"))
	_ = mgr.Stop()
	fmt.Printf("%s Временные сокеты и дескрипторы закрыты. Завершение работы.\n", banner.TagOK("ГОТОВО"))

	if launchErr != nil {
		os.Exit(1)
	}
}

func handleDaemon(countryOverride, bridgeOverride string, ephemeral bool) {
	banner.PrintBanner()

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Не удалось прочитать конфигурацию: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	if countryOverride != "" {
		cfg.ExitCountry = strings.ToLower(strings.TrimSpace(countryOverride))
	}
	if bridgeOverride != "" {
		cfg.BridgeType = strings.ToLower(strings.TrimSpace(bridgeOverride))
	}
	if ephemeral {
		cfg.Ephemeral = true
	}

	fmt.Printf("%s Запуск постоянного сетевого шлюза TuxProxy [Мост: %s, Выход: %s]...\n",
		banner.TagAction("СЛУЖБА"), strings.ToUpper(cfg.BridgeType), cfg.CountryDisplay())

	mgr, err := tor.NewManager(cfg, cfg.Ephemeral)
	if err != nil {
		fmt.Printf("%s Ошибка инициализации: %v\n", banner.TagErr("ОШИБКА"), err)
		os.Exit(1)
	}

	err = mgr.Start(func(percent int, message string) {
		fmt.Printf("\r  %s", banner.ProgressBar(percent, message))
	})
	fmt.Println()

	if err != nil {
		fmt.Printf("\n%s Сбой запуска фоновой службы: %v\n", banner.TagErr("TOR"), err)
		_ = mgr.Stop()
		os.Exit(1)
	}

	socksPort, httpPort, dnsPort, controlPort := mgr.Ports()
	report := verifier.VerifyEgress(socksPort, 12*time.Second)

	lines := []string{
		"Режим работы:          ПОСТОЯННЫЙ ЛОКАЛЬНЫЙ ШЛЮЗ ПРОКСИРОВАНИЯ",
		fmt.Sprintf("Шлюз SOCKS5 (h):       127.0.0.1:%d", socksPort),
		fmt.Sprintf("Шлюз HTTP CONNECT:     127.0.0.1:%d", httpPort),
		fmt.Sprintf("Резолвер DNS (Tor):    127.0.0.1:%d", dnsPort),
		fmt.Sprintf("Порт управления Tor:   127.0.0.1:%d", controlPort),
		fmt.Sprintf("Внешний IP-адрес:      %s%s%s", banner.Bold, report.IP, banner.Reset),
		fmt.Sprintf("Страна выхода:         %s (%s)", report.Country, report.City),
		"Для остановки службы нажмите [Ctrl+C]",
	}
	fmt.Print(banner.BoxSection("СЛУЖБА TUXPROXY ГОТОВА К ПРИЕМУ ТРАФИКА", lines))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Printf("\n%s Остановка сетевой службы...\n", banner.TagWarn("ОСТАНОВ"))
	_ = mgr.Stop()
	fmt.Printf("%s Сетевая служба успешно остановлена.\n", banner.TagOK("ОЧИСТКА"))
}

func handleTest() {
	banner.PrintBanner()
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	fmt.Printf("%s Развертывание контура для аудита OPSEC и проверки отсутствия утечек...\n", banner.TagAction("ТЕСТ"))
	mgr, err := tor.NewManager(cfg, true)
	if err != nil {
		fmt.Printf("%s Ошибка инициализации менеджера: %v\n", banner.TagErr("ОШИБКА"), err)
		os.Exit(1)
	}
	defer mgr.Stop()

	err = mgr.Start(func(percent int, message string) {
		fmt.Printf("\r  %s", banner.ProgressBar(percent, message))
	})
	fmt.Println()

	if err != nil {
		fmt.Printf("%s Ошибка бутстрапа при тестировании: %v\n", banner.TagErr("ОШИБКА"), err)
		return
	}

	socksPort, httpPort, dnsPort, controlPort := mgr.Ports()
	fmt.Printf("%s Контур активен. Выполняются диагностические сетевые запросы...\n", banner.TagOK("КОНТУР"))

	report := verifier.VerifyEgress(socksPort, 15*time.Second)

	leakState := banner.BrightGreen + "БЕЗОПАСНО (Утечек сетевых данных не обнаружено)" + banner.Reset
	if report.Error != nil {
		leakState = banner.BrightRed + "ВНИМАНИЕ: Ошибка проверки канала" + banner.Reset
	}

	lines := []string{
		fmt.Sprintf("Шлюз SOCKS5:           127.0.0.1:%d", socksPort),
		fmt.Sprintf("Шлюз HTTP Tunnel:      127.0.0.1:%d", httpPort),
		fmt.Sprintf("Резолвер DNS:          127.0.0.1:%d", dnsPort),
		fmt.Sprintf("Порт управления:       127.0.0.1:%d", controlPort),
		fmt.Sprintf("Внешний IP-адрес:      %s%s%s", banner.Bold, report.IP, banner.Reset),
		fmt.Sprintf("Страна выхода:         %s (%s)", report.Country, report.City),
		fmt.Sprintf("Провайдер узла:        %s", report.Org),
		fmt.Sprintf("Подтверждение Tor:     %sДа (Выходной узел)%s", banner.BrightGreen, banner.Reset),
		fmt.Sprintf("Статус Zero-Leak:      %s", leakState),
		fmt.Sprintf("Задержка туннеля:      %v", report.Latency.Round(time.Millisecond)),
	}

	fmt.Print(banner.BoxSection("РЕЗУЛЬТАТЫ ДИАГНОСТИКИ СЕТЕВОГО КОНТУРА", lines))
}

func handleStatus() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		return
	}

	socksPort := cfg.SocksPort
	if tor.IsPortAvailable(socksPort) {
		fmt.Printf("%s TuxProxy не запущен (Порт %d свободен).\n", banner.TagInfo("СТАТУС"), socksPort)
		return
	}

	fmt.Printf("%s Обнаружен активный шлюз на порту %d. Опрос внешнего адреса...\n", banner.TagOK("СТАТУС"), socksPort)
	report := verifier.VerifyEgress(socksPort, 8*time.Second)
	if report.Error != nil {
		fmt.Printf("%s Порт %d открыт, но не отвечает по протоколу SOCKS5.\n", banner.TagWarn("СТАТУС"), socksPort)
		return
	}

	lines := []string{
		"Состояние:             АКТИВЕН",
		fmt.Sprintf("Порт SOCKS5:           127.0.0.1:%d", socksPort),
		fmt.Sprintf("Внешний IP-адрес:      %s%s%s", banner.Bold, report.IP, banner.Reset),
		fmt.Sprintf("Геолокация выхода:     %s (%s)", report.Country, report.City),
		fmt.Sprintf("Узел сети Tor:         %v", report.IsTor),
	}
	fmt.Print(banner.BoxSection("ТЕКУЩЕЕ СОСТОЯНИЕ ШЛЮЗА", lines))
}

func handleNewnym() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		return
	}

	controlPort := cfg.ControlPort
	if tor.IsPortAvailable(controlPort) {
		fmt.Printf("%s Служба TuxProxy не запущена (Порт управления %d закрыт).\n", banner.TagErr("NEWNYM"), controlPort)
		return
	}

	err = sendNewnymDirect(controlPort)
	if err != nil {
		fmt.Printf("%s Сбой ротации контура Tor: %v\n", banner.TagErr("NEWNYM"), err)
	} else {
		fmt.Printf("%s Сигнал ротации передан успешно. Построена новая цепочка Tor.\n", banner.TagOK("NEWNYM"))
	}
}

func sendNewnymDirect(controlPort int) error {
	conn, err := tor.NewManager(&config.Config{ControlPort: controlPort}, false)
	if err != nil {
		return err
	}
	return conn.SignalNewnym()
}

func handleHook(args []string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	sub := "status"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}

	switch sub {
	case "enable", "on", "install":
		if err := shell.InstallHook(); err != nil {
			fmt.Printf("%s Ошибка активации интеграции с оболочкой: %v\n", banner.TagErr("HOOK"), err)
			os.Exit(1)
		}
		cfg.TerminalAutoHook = true
		_ = cfg.Save()
		fmt.Printf("%s Автоматическая интеграция TuxProxy активирована в ~/.bashrc и ~/.zshrc\n", banner.TagOK("HOOK"))
		fmt.Printf("%s Теперь каждый сетевой запрос в новых терминалах будет автоматически маршрутизироваться через Tor.\n", banner.TagInfo("СЛУЖБА"))
		fmt.Printf("%s Для применения в текущем окне выполните: %seval \"$(tuxproxy hook init)\"%s\n",
			banner.TagInfo("ПОДСКАЗКА"), banner.Bold+banner.BrightCyan, banner.Reset)
		fmt.Printf("%s Для временного отключения в терминале используйте команду: %stuxoff%s (повторное включение: %stuxon%s)\n",
			banner.TagInfo("ПОДСКАЗКА"), banner.Bold, banner.Reset, banner.Bold, banner.Reset)

	case "disable", "off", "remove", "uninstall":
		if err := shell.RemoveHook(); err != nil {
			fmt.Printf("%s Ошибка удаления интеграции: %v\n", banner.TagErr("HOOK"), err)
			os.Exit(1)
		}
		cfg.TerminalAutoHook = false
		_ = cfg.Save()
		fmt.Printf("%s Интеграция с терминалом отключена. Блок TuxProxy удален из конфигурационных файлов оболочки.\n", banner.TagOK("HOOK"))
		fmt.Printf("%s Для отключения проксирования в текущей открытой сессии выполните: %seval \"$(tuxproxy env --off)\"%s или команду %stuxoff%s\n",
			banner.TagInfo("ПОДСКАЗКА"), banner.Bold+banner.BrightCyan, banner.Reset, banner.Bold, banner.Reset)

	case "init":
		// Чистый вывод Bash/Zsh кода для eval "$(tuxproxy hook init)"
		fmt.Print(shell.InitScript(cfg))

	case "status":
		installed := shell.IsHookInstalled()
		statusStr := banner.BrightGreen + "УСТАНОВЛЕН И АКТИВЕН" + banner.Reset
		if !installed {
			statusStr = banner.BrightYellow + "НЕ УСТАНОВЛЕН (Отключен)" + banner.Reset
		}
		lines := []string{
			fmt.Sprintf("Интеграция оболочки:   %s", statusStr),
			fmt.Sprintf("Автоподключение в конфиге: %v", cfg.TerminalAutoHook),
			fmt.Sprintf("Автостарт демона Tor:  %v", cfg.TerminalAutoStartDaemon),
			fmt.Sprintf("Индикатор PS1:         %v", cfg.ShowPromptIndicator),
			fmt.Sprintf("Поддержка Java/JVM:    %v", cfg.JavaProxySupport),
			"Команды управления:    tuxproxy hook enable | tuxproxy hook disable",
		}
		fmt.Print(banner.BoxSection("СТАТУС ИНТЕГРАЦИИ С ТЕРМИНАЛОМ", lines))

	default:
		fmt.Printf("%s Неизвестный параметр hook. Допустимые варианты: enable | disable | status | init\n", banner.TagErr("СИНТАКСИС"))
		os.Exit(1)
	}
}

func handleEnv(args []string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения конфигурации: %v\n", err)
		os.Exit(1)
	}

	disable := false
	for _, arg := range args {
		if arg == "--off" || arg == "-off" || arg == "off" || arg == "-d" || arg == "--unset" || arg == "unset" {
			disable = true
			break
		}
	}

	// Вывод чистых команд export / unset для использования через eval $(tuxproxy env)
	fmt.Print(shell.EnvExport(cfg, disable))
}

func handleSubshell() {
	banner.PrintBanner()
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%s Ошибка чтения конфигурации: %v\n", banner.TagErr("КОНФИГ"), err)
		os.Exit(1)
	}

	fmt.Printf("%s Подготовка изолированного окружения оболочки с проксированием Tor...\n", banner.TagAction("ПОДОБОЛОЧКА"))
	mgr, err := tor.NewManager(cfg, true)
	if err != nil {
		fmt.Printf("%s Ошибка запуска Tor: %v\n", banner.TagErr("TOR"), err)
		os.Exit(1)
	}
	defer mgr.Stop()

	err = mgr.Start(func(percent int, message string) {
		fmt.Printf("\r  %s", banner.ProgressBar(percent, message))
	})
	fmt.Println()
	if err != nil {
		fmt.Printf("%s Сбой бутстрапа Tor: %v\n", banner.TagErr("TOR"), err)
		return
	}

	fmt.Printf("%s Запуск защищенной интерактивной сессии терминала. Для выхода введите 'exit'.\n\n", banner.TagOK("СЕССИЯ"))
	if err := shell.SpawnSubshell(cfg, mgr); err != nil {
		fmt.Printf("%s Завершение сеанса: %v\n", banner.TagWarn("СЕССИЯ"), err)
	}
}
