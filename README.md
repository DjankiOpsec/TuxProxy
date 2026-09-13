# TUXPROXY :: ИЗОЛЯЦИЯ ПРОЦЕССОВ И СЕТЕВОЕ ТУННЕЛИРОВАНИЕ ДЛЯ LINUX

<p align="center">
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Language-Go%201.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Platform Linux"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/Security-Fail--Closed%20OPSEC-brightgreen?style=for-the-badge&logo=shield" alt="OPSEC"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Network-Tor%20Isolated-7D4698?style=for-the-badge&logo=torproject&logoColor=white" alt="Tor Network"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/kondrakov408-sys/TuxProxy?style=flat-square&color=00ADD8" alt="Top Language">
  <img src="https://img.shields.io/github/repo-size/kondrakov408-sys/TuxProxy?style=flat-square&color=informational" alt="Repo Size">
  <img src="https://img.shields.io/github/stars/kondrakov408-sys/TuxProxy?style=flat-square&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/issues/kondrakov408-sys/TuxProxy?style=flat-square&color=orange" alt="Issues">
</p>

```text
========================================================================
 TUXPROXY :: Комплекс сетевой изоляции процессов Linux v1.0.0
 Архитектура NetNS-Gateway | Маршрутизация Tor | Пакетный фильтр nftables
========================================================================
```

**TuxProxy** — системная утилита на языке Go для операционных систем семейства Linux, предназначенная для маршрутизации трафика прикладных программ и сессий терминала через изолированный контур Tor с защитой от утечек данных, поддержкой Pluggable Transports (Snowflake, obfs4, WebTunnel), контролем юрисдикций выхода (Exit Nodes) и ядерной изоляцией сетевого стека (`netns-gateway`).

---

## 1. Архитектура комплекса

```
+--------------------------------------------------------------------------------------------------+
|                                    TUXPROXY АРХИТЕКТУРА (GO)                                     |
+----------------------------------+----------------------------------+----------------------------+
                                   |                                  |
                                   v                                  v
+------------------------------------+      +------------------------------------------------------+
|  GUI SETTINGS STUDIO (127.0.0.1)   |      |            СУПЕРВИЗОР СЕТЕВОГО КОНТУРА TOR           |
+------------------------------------+      +------------------------------------------------------+
| * Маршрутизация & Геолокация       |      | * Изолированный супервизор tor (Daemon / On-demand)  |
| * Обход цензуры (Snowflake/obfs4)  |      | * Unix ControlSocket (0700 dir, 0600 cookie auth)    |
| * Управление Shell Hook & PS1      |      | * SOCKS5h шлюз с удалённым DNS (127.0.0.1:9050)      |
| * Генератор безопасных команд CLI  |      | * HTTP CONNECT Tunnel шлюз (127.0.0.1:9080)          |
| * Анти-0.0.0.0 аудит слушателей    |      | * Локальный DNS-резолвер DNSPort (127.0.0.1:9053)    |
| * Fail-Closed аварийный watchdog   |      | * Защита: ClientUseIPv6 0, SafeLogging 1             |
+------------------------------------+      +--------------------------+---------------------------+
                                                                       |
                 +-----------------------------------------------------+-----------------------------------+
                 |                                                     |                                   |
                 v                                                     v                                   v
+----------------------------------+          +----------------------------------+        +----------------------------------+
|    NETNS-GATEWAY (ХАРДВАРНЫЙ)    |          |    ПЕСОЧНИЦА CHROMIUM/ELECTRON   |        |   ПЕРЕХВАТЧИК СОКЕТОВ LIBC       |
+----------------------------------+          +----------------------------------+        +----------------------------------+
| * Ядерный сетевой namespace      |          | * Antigravity IDE, VS Code       |        | * proxychains4 (LD_PRELOAD)      |
| * Изолированная пара veth        |          | * Chrome, Brave, Discord, Slack  |        | * Telegram Desktop, C/C++ бинар- |
| * Zero-Forwarding & Zero-NAT     |          | * --host-resolver-rules (Блок)   |          ники, игры, сокетные утилиты     |
| * nftables: принудительный DNAT  |          | * --webrtc-ip-handling-policy    |        | * Перехват connect / getaddrinfo |
|   порта 53 на Tor DNS            |          | * Отключение телеметрии браузера |        | * Строгая цепочка strict_chain   |
| * Сброс прав в $SUDO_USER        |          | * Переменные окружения POSIX     |        | * Подсеть remote_dns_subnet 224  |
+----------------------------------+          +----------------------------------+        +----------------------------------+
                 |                                                     |                                   |
                 +-----------------------------------------------------+-----------------------------------+
                                                       |
                                                       v  (Многослойное Onion-шифрование)
                [ Мост: Snowflake / obfs4 ] ---> [ Промежуточный релей ] ---> [ Выходной узел ({us}) ] ---> Интернет
```

---

## 2. Модули системы

### 2.1. NetNS Engine (`netns-gateway`)
Наиболее надежный профиль изоляции (`tuxproxy open --netns <app>`):
* **Выделенный Network Namespace:** создается изолированный сетевой стек ядра Linux (`tuxproxy-<id>`) с поднятым `lo`.
* **Виртуальная пара veth:** интерфейсы `veth-tux<id>` (хост, `10.200.<id>.1/24`) и `vpeer-tux<id>` (namespace, `10.200.<id>.2/24`).
* **Zero-Forwarding & Zero-NAT:**
  * Форвардинг пакетов строго отключен на уровне интерфейса: `sysctl net.ipv4.conf.veth-tux*.forwarding=0`.
  * Глобальный хостовый `ip_forward` **не затрагивается**, предотвращая сбои Docker, KVM и VPN.
  * Прямой NAT/MASQUERADE отсутствует — прямой выход в публичную сеть физически невозможен.
* **Пакетный фильтр `nftables`:**
  * Атомарная загрузка правил через транзакционный `nft -f -`.
  * DNAT входящих DNS-запросов: UDP/TCP порт 53 перенаправляется на `10.200.<id>.1:9053` (Tor DNSPort).
  * Разрешены только локальные соединения к шлюзу (SOCKS 9050, DNS 9053). Любой прямой трафик в WAN отбрасывается ядром (`drop`).
* **DNS в пространстве имен:** автоматический монтаж изолированного `/etc/netns/<id>/resolv.conf` с `nameserver 10.200.<id>.1`.
* **Сброс привилегий:** запуск целевого процесса через `runuser -u $SUDO_USER --` исключает запуск пользовательского ПО с правами root.
* **Безопасный сборщик мусора (GC):** при старте сканируются осиротевшие namespaces; парсинг `/proc/<pid>/stat` использует границу последней закрывающей скобки `LastIndex(")")` и валидацию `starttime` (поле 22), предотвращая сбои из-за переиспользования PID.

### 2.2. Супервизор Tor и Unix ControlSocket
* Запуск локального контура Tor с изолированным рантайм-каталогом `0700` (`$XDG_RUNTIME_DIR/tuxproxy/session-<id>`).
* Управление через **Unix Domain Socket** с обязательной cookie-аутентификацией (`0600`).
* Автоматическая проверка слушающих сокетов: обнаружение привязки на `0.0.0.0` немедленно прерывает выполнение.
* Фоновый watchdog с событийным контролем состояния (0 мс задержки на закрытие сокета).

### 2.3. Shell Hook (Интеграция с терминалом)
* **Межпроцессная блокировка:** `syscall.Flock` на `~/.tuxproxy.lock` гарантирует отсутствие гонок при одновременном открытии вкладок терминала.
* **Атомарная запись с двойным fsync:**
  1. Запись во временный файл в том же каталоге (`~/.bashrc.tmp.<rand>`).
  2. `tmpFile.Sync()` для сброса буферов на диск.
  3. Сохранение исходных прав доступа (`os.Chmod`).
  4. Атомарная замена через `os.Rename()`.
  5. `dir.Sync()` родительского каталога для надежной фиксации dentry в файловой системе.
* **Изоляция маркеров:** модифицируется исключительно блок между `# >>> TuxProxy Shell Integration >>>` и `# <<< TuxProxy Shell Integration <<<`. Пользовательские алиасы и скрипты остаются нетронутыми.
* **Retention Policy для бэкапов:** автоматическое создание резервных копий `~/.bashrc.tuxproxy.bak.<timestamp>` со строгим сохранением **последних 3 копий**.
* **Неинтерактивный гард:**
  ```bash
  case "$-" in
      *i*) ;;
        *) return 0 2>/dev/null || exit 0 ;;
  esac
  [ -z "$PS1" ] && return 0 2>/dev/null
  ```
  Исключает поломку `scp`, `rsync`, `sftp`, `git-over-ssh` и фоновых скриптов автоматизации.

---

## 3. Матрица профилей изоляции

Подробное описание модели угроз и границ применимости приведено в [SECURITY.md](SECURITY.md).

| Профиль | Вызов CLI | Привилегии | Классы приложений | Надежность изоляции |
| :--- | :--- | :--- | :--- | :--- |
| **`netns-gateway`** | `tuxproxy open -n <app>` | `sudo` / `CAP_NET_ADMIN` | Любые приложения, Go, Rust, raw сокеты | **Максимальная (Ядро / nftables)** |
| **`proxychains`** | `tuxproxy open -p <app>` | Обычный пользователь | Динамические ELF (Telegram, C/C++) | **Средняя (libc LD_PRELOAD)** |
| **`electron`** | `tuxproxy open <app>` | Обычный пользователь | Electron / Chromium (Antigravity, Chrome) | **Средняя (Флаги песочницы)** |
| **`env`** | `eval "$(tuxproxy env)"` | Обычный пользователь | POSIX CLI (`curl`, `git`, `python`, `cargo`) | **Базовая (Переменные окружения)** |

---

## 4. Справочник команд CLI

```text
ИСПОЛЬЗОВАНИЕ:
  tuxproxy [команда] [опции]

КОМАНДЫ:
  open <приложение> [опции]     Запуск приложения в защищенном контуре
  hook <enable|disable|status>  Управление автопроксированием терминалов (~/.bashrc, ~/.zshrc)
  env [--off]                   Вывод команд экспорта/сброса переменных окружения
  shell                         Запуск изолированной интерактивной подоболочки
  daemon                        Запуск фонового шлюза Tor
  test                          Синтетический аудит утечек трафика (Direct TCP, DNS, IPv6)
  newnym                        Ротация onion-контура (смена выходного IP)
  status                        Проверка состояния шлюза и сетевых интерфейсов
  gui                           Открыть графический веб-интерфейс настроек (127.0.0.1:9099)
  settings                      Интерактивное TUI-меню настроек

ФЛАГИ КОМАНДЫ OPEN:
  -n, --netns                   Запуск в аппаратном ядерном пространстве имен (netns-gateway)
  -p, --proxychains             Принудительный перехват сокетов через proxychains4
  -c, --country <ISO>           Код страны выхода (us, de, nl, ch, se, sg и др.)
  -b, --bridge <тип>            Транспорт обхода блокировок: snowflake, obfs4, webtunnel, none
  -e, --ephemeral               Бесследный режим работы в RAM (tmpfs)
```

### Примеры практического использования:

```bash
# 1. Запуск браузера или IDE в аппаратном NetNS-шлюзе (наивысший уровень защиты)
sudo tuxproxy open --netns google-chrome-stable
sudo tuxproxy open -n antigravity-ide

# 2. Запуск приложения с перехватом сокетов через proxychains
tuxproxy open --proxychains telegram-desktop

# 3. Запуск среды разработки IntelliJ IDEA с выбором выходной ноды Швейцарии
tuxproxy open idea --country ch

# 4. Активация хука для всех новых сессий bash/zsh
tuxproxy hook enable

# 5. Проверка текущего статуса хука
tuxproxy hook status

# 6. Удаление хука из конфигурационных файлов
tuxproxy hook disable

# 7. Запуск синтетического аудита на отсутствие прямых утечек
tuxproxy test
```

---

## 5. Сборка и установка

### Системные требования:
* ОС: Linux (ядро 5.10+)
* Утилиты: `iproute2`, `nftables` (для режима `--netns`), `tor`, `proxychains-ng` (опционально)

```bash
# Arch Linux / CachyOS / Manjaro
sudo pacman -S tor proxychains-ng iproute2 nftables

# Debian / Ubuntu / Mint
sudo apt update && sudo apt install -y tor proxychains4 iproute2 nftables
```

### Сборка из исходников:
```bash
git clone https://github.com/kondrakov408-sys/TuxProxy.git
cd TuxProxy

# Сборка бинарника
make

# Установка в ~/.local/bin/tuxproxy
make install

# Запуск тестов
make test
```

---

## 6. Синтетическое тестирование утечек

В репозиторий включен пакет провокационных синтетических тестов [`test/synthetic/`](test/synthetic/), имитирующий агрессивные попытки обхода контура:
* `leaker-direct-tcp`: прямая попытка подключения к контрольному сокету хоста мимо прокси (должна падать по `ENETUNREACH` / timeout).
* `leaker-dns`: попытка отправки сырого UDP-пакета на порт 53 публичного DNS (перехватывается и заворачивается в Tor DNSPort).
* `leaker-ipv6`: попытка установки соединения по IPv6 при отключенном стеке.

Запуск тестов:
```bash
# Непривилегированные тесты
go test -v -race ./...

# Привилегированные тесты ядерной изоляции NetNS (требуется sudo)
sudo go test -v -race -run TestPrivilegedNetNSLeakProof ./test/synthetic/...
```

---

## 7. Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
TuxProxy не содержит телеметрии, скрытых сетевых вызовов и сторонних аналитических модулей.
