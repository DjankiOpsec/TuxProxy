package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"tuxproxy/internal/banner"
	"tuxproxy/internal/config"
	"tuxproxy/internal/tor"
	"tuxproxy/internal/verifier"
)

// RunSettingsMenu запускает интерактивное меню настройки параметров безопасности
func RunSettingsMenu(cfg *config.Config) error {
	for {
		strictStr := "Строгая привязка (разрыв при недоступности)"
		if !cfg.StrictNodes {
			strictStr = "Мягкая (разрешён резервный выход)"
		}

		ephemeralStr := "Отключен (кэширование консенсуса в ~/.local/share)"
		if cfg.Ephemeral {
			ephemeralStr = "Включен (работа исключительно в RAM/tmpfs)"
		}

		menuItems := []MenuItem{
			{
				Key:         "country",
				Title:       fmt.Sprintf("Страна выхода (Exit Node): %s", cfg.CountryDisplay()),
				Description: "Выбор целевой юрисдикции выходного узла (США, Германия, Нидерланды и др.)",
			},
			{
				Key:         "strict",
				Title:       fmt.Sprintf("Политика изоляции узлов: %s", strictStr),
				Description: "Исключает случайный выход через нецелевые юрисдикции при сбое",
			},
			{
				Key:         "bridge",
				Title:       fmt.Sprintf("Транспорт обхода DPI (Мост): %s", strings.ToUpper(cfg.BridgeType)),
				Description: "Snowflake (WebRTC + Google AMP), obfs4/Lyrebird, WebTunnel или прямое",
			},
			{
				Key:         "leak",
				Title:       "Параметры предотвращения утечек (Zero-Leak OPSEC)",
				Description: "Настройка DNS-изоляции (socks5h), подавления WebRTC и блокировки IPv6",
			},
			{
				Key:         "ports",
				Title:       fmt.Sprintf("Сетевые интерфейсы (SOCKS5: %d, HTTP: %d, DNS: %d)", cfg.SocksPort, cfg.HTTPPort, cfg.DNSPort),
				Description: "Конфигурация локальных портов прослушивания",
			},
			{
				Key:         "ephemeral",
				Title:       fmt.Sprintf("Режим отсутствия следов на диске: %s", ephemeralStr),
				Description: "Уничтожение всех дескрипторов и логов сразу после закрытия процесса",
			},
			{
				Key:         "test",
				Title:       "Диагностика: Проверка подключения и аудит на утечки",
				Description: "Запуск временного контура Tor и проверка внешнего IP/DNS",
			},
			{
				Key:         "save",
				Title:       fmt.Sprintf("%s[СОХРАНИТЬ] Записать параметры в конфигурацию и выйти%s", banner.Bold, banner.Reset),
				Description: "Запись в ~/.config/tuxproxy/config.json",
			},
			{
				Key:         "exit",
				Title:       "Выход без сохранения",
				Description: "Закрыть меню конфигурации без изменения текущих параметров",
			},
		}

		idx, err := SelectPrompt("КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ И МАРШРУТИЗАЦИИ TUXPROXY", menuItems, 0)
		if err != nil || idx < 0 {
			return nil
		}

		selected := menuItems[idx].Key
		switch selected {
		case "country":
			configureCountry(cfg)
		case "strict":
			cfg.StrictNodes = !cfg.StrictNodes
		case "bridge":
			configureBridge(cfg)
		case "leak":
			configureLeakGuards(cfg)
		case "ports":
			configurePorts(cfg)
		case "ephemeral":
			cfg.Ephemeral = !cfg.Ephemeral
		case "test":
			runLiveTest(cfg)
		case "save":
			if err := cfg.Save(); err != nil {
				fmt.Printf("\n%s Ошибка записи конфигурации: %v\n", banner.TagErr("ОШИБКА"), err)
			} else {
				fmt.Printf("\n%s Конфигурация успешно сохранена в %s\n", banner.TagOK("ЗАПИСАНО"), config.GetConfigFile())
			}
			time.Sleep(1 * time.Second)
			return nil
		case "exit":
			return nil
		}
	}
}

func configureCountry(cfg *config.Config) {
	countries := []struct {
		code, name string
	}{
		{"us", "Соединённые Штаты Америки (US)"},
		{"de", "Германия (DE)"},
		{"nl", "Нидерланды (NL)"},
		{"ch", "Швейцария (CH)"},
		{"ca", "Канада (CA)"},
		{"gb", "Великобритания (GB)"},
		{"sg", "Сингапур (SG)"},
		{"se", "Швеция (SE)"},
		{"fr", "Франция (FR)"},
		{"any", "Любая страна (Выбор по минимальной задержке)"},
		{"custom", "Ввести произвольный 2-буквенный ISO-код страны..."},
	}

	items := make([]MenuItem, len(countries))
	curr := strings.ToLower(cfg.ExitCountry)
	defaultIdx := 0

	for i, c := range countries {
		items[i] = MenuItem{
			Key:    c.code,
			Title:  c.name,
			Active: curr == c.code,
		}
		if curr == c.code {
			defaultIdx = i
		}
	}

	idx, err := SelectPrompt("ВЫБОР СТРАНЫ ВЫХОДНОГО УЗЛА (EXIT NODE)", items, defaultIdx)
	if err != nil || idx < 0 {
		return
	}

	if items[idx].Key == "custom" {
		code := ReadInput("Введите 2-буквенный ISO-код (например, fi, at, jp)", "us")
		cfg.ExitCountry = strings.ToLower(strings.TrimSpace(code))
	} else {
		cfg.ExitCountry = items[idx].Key
	}
}

func configureBridge(cfg *config.Config) {
	bridges := []struct {
		bType, title, desc string
	}{
		{"snowflake", "Snowflake (WebRTC + Google AMP)", "Эффективный обход блокировок ТСПУ/DPI через инфраструктуру Google CDN (Рекомендуется)"},
		{"obfs4", "obfs4 / Lyrebird", "Скремблирование сигнатуры пакетов под энтропийный шум"},
		{"webtunnel", "WebTunnel (Маскировка под HTTPS)", "Мимикрия протокола Tor под обычные веб-сессии HTTP/2"},
		{"none", "Прямое подключение (Без мостов)", "Для работы в сетях без активной DPI-фильтрации"},
		{"custom", "Пользовательские строки мостов (Custom)", "Ручной ввод актуальных строк мостов из bridges.torproject.org"},
	}

	items := make([]MenuItem, len(bridges))
	defaultIdx := 0
	curr := strings.ToLower(cfg.BridgeType)

	for i, b := range bridges {
		items[i] = MenuItem{
			Key:         b.bType,
			Title:       b.title,
			Description: b.desc,
			Active:      curr == b.bType,
		}
		if curr == b.bType {
			defaultIdx = i
		}
	}

	idx, err := SelectPrompt("ВЫБОР ТРАНСПОРТА ОБХОДА БЛОКИРОВОК (PLUGGABLE TRANSPORT)", items, defaultIdx)
	if err != nil || idx < 0 {
		return
	}

	cfg.BridgeType = items[idx].Key

	if cfg.BridgeType == "obfs4" || cfg.BridgeType == "webtunnel" || cfg.BridgeType == "custom" {
		fmt.Printf("\n%s Введите строку моста (полученную от @GetBridgesBot или bridges.torproject.org):\n", banner.TagInfo("МОСТ"))
		line := ReadInput("Строка моста", "")
		if strings.TrimSpace(line) != "" {
			cfg.CustomBridges = []string{strings.TrimSpace(line)}
		}
	}
}

func configureLeakGuards(cfg *config.Config) {
	for {
		state := func(val bool) string {
			if val {
				return banner.BrightGreen + "[ВКЛЮЧЕНО]" + banner.Reset
			}
			return banner.BrightRed + "[ВЫКЛЮЧЕНО]" + banner.Reset
		}

		items := []MenuItem{
			{
				Key:         "dns",
				Title:       fmt.Sprintf("Удалённый DNS-резолв (socks5h + host-resolver): %s", state(cfg.PreventDNSLeak)),
				Description: "Исключает утечки запросов к системному провайдерскому DNS",
			},
			{
				Key:         "webrtc",
				Title:       fmt.Sprintf("Блокировка утечек через WebRTC (disable UDP): %s", state(cfg.PreventWebRTCLeak)),
				Description: "Блокирует не-проксированные STUN/TURN UDP пакеты в браузерах и Electron",
			},
			{
				Key:         "ipv6",
				Title:       fmt.Sprintf("Отключение dual-stack IPv6 (ClientUseIPv6 0): %s", state(cfg.DisableIPv6)),
				Description: "Предотвращает утечку трафика в обход Tor через интерфейс IPv6",
			},
			{
				Key:         "safelog",
				Title:       fmt.Sprintf("Очистка чувствительных данных в логах (SafeLogging): %s", state(cfg.SafeLogging)),
				Description: "Удаляет реальные сетевые адреса и хосты из журналов работы",
			},
			{
				Key:         "proxychains",
				Title:       fmt.Sprintf("Принудительная обертка Proxychains4: %s", state(cfg.ForceProxychains)),
				Description: "Перехват сетевых вызовов через LD_PRELOAD для сторонних бинарников",
			},
			{
				Key:   "back",
				Title: "<-- Вернуться в главное меню",
			},
		}

		idx, err := SelectPrompt("МЕХАНИЗМЫ ПРЕДОТВРАЩЕНИЯ УТЕЧЕК ДАННЫХ (ZERO-LEAK)", items, 0)
		if err != nil || idx < 0 {
			return
		}

		switch items[idx].Key {
		case "dns":
			cfg.PreventDNSLeak = !cfg.PreventDNSLeak
		case "webrtc":
			cfg.PreventWebRTCLeak = !cfg.PreventWebRTCLeak
		case "ipv6":
			cfg.DisableIPv6 = !cfg.DisableIPv6
		case "safelog":
			cfg.SafeLogging = !cfg.SafeLogging
		case "proxychains":
			cfg.ForceProxychains = !cfg.ForceProxychains
		case "back":
			return
		}
	}
}

func configurePorts(cfg *config.Config) {
	fmt.Printf("\n%s Конфигурация локальных сетевых портов (0 для автовыбора):\n", banner.TagInfo("ПОРТЫ"))
	sStr := ReadInput("Порт SOCKS5", strconv.Itoa(cfg.SocksPort))
	if p, err := strconv.Atoi(sStr); err == nil {
		cfg.SocksPort = p
	}

	hStr := ReadInput("Порт HTTP Tunnel", strconv.Itoa(cfg.HTTPPort))
	if p, err := strconv.Atoi(hStr); err == nil {
		cfg.HTTPPort = p
	}

	dStr := ReadInput("Порт DNSPort", strconv.Itoa(cfg.DNSPort))
	if p, err := strconv.Atoi(dStr); err == nil {
		cfg.DNSPort = p
	}

	cStr := ReadInput("Порт ControlPort", strconv.Itoa(cfg.ControlPort))
	if p, err := strconv.Atoi(cStr); err == nil {
		cfg.ControlPort = p
	}
}

func runLiveTest(cfg *config.Config) {
	fmt.Printf("\n%s Развертывание изолированного контура Tor для аудита безопасности...\n", banner.TagAction("ТЕСТ"))
	mgr, err := tor.NewManager(cfg, true)
	if err != nil {
		fmt.Printf("%s Сбой инициализации менеджера Tor: %v\n", banner.TagErr("ОШИБКА"), err)
		return
	}
	defer mgr.Stop()

	err = mgr.Start(func(percent int, message string) {
		fmt.Printf("\r  %s", banner.ProgressBar(percent, message))
	})
	fmt.Println()

	if err != nil {
		fmt.Printf("%s Не удалось установить контур Tor: %v\n", banner.TagErr("ОШИБКА"), err)
		ReadInput("Нажмите [Enter] для возврата", "")
		return
	}

	fmt.Printf("%s Контур Tor установлен. Выполняется проверка выходного шлюза...\n", banner.TagOK("КОНТУР"))
	socksPort, httpPort, dnsPort, _ := mgr.Ports()

	report := verifier.VerifyEgress(socksPort, 15*time.Second)
	if report.Error != nil {
		fmt.Printf("%s Ошибка валидации выходного шлюза: %v\n", banner.TagErr("ОШИБКА"), report.Error)
	} else {
		lines := []string{
			fmt.Sprintf("Интерфейс SOCKS5:      127.0.0.1:%d", socksPort),
			fmt.Sprintf("Интерфейс HTTP Tunnel: 127.0.0.1:%d", httpPort),
			fmt.Sprintf("Резолвер DNS (Tor):    127.0.0.1:%d", dnsPort),
			fmt.Sprintf("Внешний IP-адрес:      %s%s%s", banner.Bold, report.IP, banner.Reset),
			fmt.Sprintf("Геолокация:            %s (%s)", report.Country, report.City),
			fmt.Sprintf("Провайдер узла:        %s", report.Org),
			fmt.Sprintf("Статус узла Tor:       %sПодтверждён (Выходной релей)%s", banner.BrightGreen, banner.Reset),
			fmt.Sprintf("Задержка туннеля:      %v", report.Latency.Round(time.Millisecond)),
		}
		fmt.Print(banner.BoxSection("РЕЗУЛЬТАТЫ АУДИТА БЕЗОПАСНОСТИ", lines))
	}

	ReadInput("Нажмите [Enter] для возврата в меню", "")
}
