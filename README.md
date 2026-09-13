# TUXPROXY :: ИЗОЛЯЦИЯ ПРОЦЕССОВ И ЗАЩИТА СЕТЕВОГО ТРАФИКА

<p align="center">
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Language-Go%201.27-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Platform Linux"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Security-Zero--Leak%20OPSEC-brightgreen?style=for-the-badge&logo=shield" alt="OPSEC"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy"><img src="https://img.shields.io/badge/Network-Tor%20Isolated-7D4698?style=for-the-badge&logo=torproject&logoColor=white" alt="Tor Network"></a>
  <a href="https://github.com/kondrakov408-sys/TuxProxy/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/kondrakov408-sys/TuxProxy?style=flat-square&color=00ADD8" alt="Top Language">
  <img src="https://img.shields.io/github/languages/count/kondrakov408-sys/TuxProxy?style=flat-square&color=blue" alt="Languages Count">
  <img src="https://img.shields.io/github/repo-size/kondrakov408-sys/TuxProxy?style=flat-square&color=informational" alt="Repo Size">
  <img src="https://img.shields.io/github/stars/kondrakov408-sys/TuxProxy?style=flat-square&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/forks/kondrakov408-sys/TuxProxy?style=flat-square&color=lightgrey" alt="Forks">
  <img src="https://img.shields.io/github/issues/kondrakov408-sys/TuxProxy?style=flat-square&color=orange" alt="Issues">
</p>

```text
========================================================================
 TUXPROXY :: Комплекс изоляции процессов и защиты сетевого трафика v1.0.0
 Среда предотвращения утечек (Zero-Leak) | Маршрутизация Tor | Anti-DPI
========================================================================
```

**TuxProxy** — специализированный комплекс системного уровня на языке Go для операционных систем семейства Linux, предназначенный для маршрутизации сетевого трафика любых приложений и сессий терминала через изолированный контур Tor с нулевыми утечками данных (Zero-Leak OPSEC), активным преодолением DPI-фильтрации (Snowflake, obfs4, WebTunnel) и строгим контролем юрисдикции выхода (Exit Nodes).

---

## 1. Архитектурная модель и разделение ответственности

В соответствии с требованиями безопасности архитектура TuxProxy строго разделяет функции **конфигурации** и **исполнения**:

1. **Графический интерфейс (Web GUI Settings Studio):**
   * Предназначен **исключительно для детальной настройки параметров безопасности, мостов, портов, маршрутизации и интеграций**.
   * Прямой запуск прикладных программ из веб-браузера принципиально исключен: современные браузерные песочницы изолируют сокеты, искажают системные сигналы (`SIGINT`/`SIGTERM`) и не позволяют надежно перехватывать системные дескрипторы целевых процессов.
   * Содержит интерактивный генератор команд CLI с возможностью копирования готовой строки запуска в один клик.

2. **Интерфейс командной строки (CLI Launcher):**
   * Является **основным и единственным механизмом запуска изолированных процессов**.
   * Осуществляет супервизию жизненного цикла: разворачивает временный или подключается к активному контуру Tor, выполняет верификацию сетевого выхода (Egress Audit), инжектирует флаги песочницы и контролирует дочерний процесс до полного завершения.

3. **Интеграция с сессиями терминала (Shell Hook):**
   * Предоставляет механизм бесшовного автоматического проксирования всех интерактивных сессий командной строки (`bash`, `zsh`).
   * Маршрутизирует любые запросы (`curl`, `wget`, `git`, `python`, `pip`, `npm`, `apt`, `cargo`, `docker-cli`) через Tor без необходимости ручного ввода прокси-флагов.
   * Управляется командами `tuxproxy hook enable` / `disable`, а также локальными терминальными вызовами `tuxoff` / `tuxon` / `tuxip`.

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
| * Обход цензуры (Snowflake/obfs4)  |      | * SOCKS5h шлюз с удалённым DNS       (127.0.0.1:9050)|
| * Настройка Shell Hook & PS1       |      | * HTTP CONNECT Tunnel шлюз           (127.0.0.1:9080)|
| * Универсальные режимы изоляции    |      | * Локальный DNS-резолвер Tor DNSPort (127.0.0.1:9053)|
| * Сетевые порты & Zero-Leak OPSEC  |      | * Управление контуром ControlPort    (127.0.0.1:9051)|
| * Генератор CLI-команд запуска     |      | * Защита от утечек: ClientUseIPv6 0, SafeLogging 1   |
+------------------------------------+      +--------------------------+---------------------------+
                                                                       |
                 +-----------------------------------------------------+-----------------------------------+
                 |                                                     |                                   |
                 v                                                     v                                   v
+----------------------------------+          +----------------------------------+        +----------------------------------+
|    ПЕСОЧНИЦА CHROMIUM/ELECTRON   |          |         JAVA / JVM СРЕДА         |        |   ПЕРЕХВАТЧИК СИСТЕМНЫХ СОКЕТОВ  |
+----------------------------------+          +----------------------------------+        +----------------------------------+
| * Antigravity IDE, VS Code       |          | * IntelliJ IDEA, PyCharm         |        | * proxychains4 (LD_PRELOAD)      |
| * Chrome, Brave, Discord, Slack  |          | * Android Studio, Gradle, Maven  |        | * Telegram Desktop, C/C++ бинар- |
| * --host-resolver-rules (Блок)   |          | * _JAVA_OPTIONS (SOCKS5h/HTTP)   |          ники, игры, сокетные утилиты     |
| * --webrtc-ip-handling-policy    |          | * JAVA_TOOL_OPTIONS              |        | * Перехват libc connect/getaddr  |
| * Отключение телеметрии браузера |          | * Remote DNS через SOCKS5        |        | * Строгая изоляция strict_chain  |
+----------------------------------+          +----------------------------------+        +----------------------------------+
                 |                                                     |                                   |
                 +-----------------------------------------------------+-----------------------------------+
                                                       |
                                                       v  (Многослойное Onion-шифрование)
                [ Мост: Snowflake / obfs4 ] ---> [ Промежуточный релей ] ---> [ Выходной узел ({us}) ] ---> Интернет
```

---

## 2. Модель угроз и механизмы предотвращения утечек (Zero-Leak)

### 2.1. Предотвращение утечек DNS-запросов (DNS Leakage)
* **Вектор уязвимости:** При использовании протокола `socks5://` доменное имя резолвится локальной функцией `getaddrinfo()` через системные DNS-серверы хоста (`/etc/resolv.conf`). Местный интернет-провайдер фиксирует полный список посещаемых доменов.
* **Реализация защиты в TuxProxy:**
  1. Принудительно устанавливается протокол `socks5h://`. Префикс `h` директивно предписывает сетевому клиенту передавать нераспознанное доменное имя внутрь туннеля для удалённого резолва выходным узлом Tor.
  2. Для приложений на базе Chromium и Electron (включая **Antigravity IDE**) принудительно применяется флаг ядра:
     ```bash
     --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
     ```
     Данное правило полностью отключает внутренний асинхронный резолвер браузера: любые попытки прямого DNS-запроса возвращают статус `NOTFOUND`, делая физически невозможным обращение к серверам хоста.
  3. В рантайме Tor активен локальный резолвер `DNSPort 127.0.0.1:9053`.

### 2.2. Подавление утечек реального адреса через WebRTC (STUN Reflection)
* **Вектор уязвимости:** Подсистема WebRTC в браузерах и Electron использует протоколы STUN/TURN для прямого установления P2P-соединений. STUN-запросы передаются по UDP мимо SOCKS/HTTP-прокси, в результате чего внешний сервер получает белый IP-адрес сетевой карты хоста.
* **Реализация защиты в TuxProxy:** В целевой процесс инжектируются флаги:
  ```bash
  --webrtc-ip-handling-policy=disable_non_proxied_udp
  --enforce-webrtc-ip-permission-check
  ```
  Это запрещает использование сетевых интерфейсов хоста для не-проксированного UDP-трафика и блокирует сбор локальных и внешних IP-кандидатов WebRTC.

### 2.3. Ликвидация утечек через Dual-Stack IPv6
* **Вектор уязвимости:** Если провайдер связи поддерживает IPv6, сетевой стек ОС при наличии DNS AAAA-записи направляет трафик по нативному IPv6-маршруту мимо IPv4-туннеля Tor.
* **Реализация защиты в TuxProxy:** В рантайме Tor директивно отключается стек IPv6:
  ```text
  ClientUseIPv6 0
  ClientPreferIPv6ORPort 0
  ```
  Это гарантирует, что трафик не покинет хост в обход защищенного контура.

### 2.4. Подавление телеметрии и фонового сбора данных
* Для сред Chromium/Electron автоматически применяются параметры:
  * `--disable-breakpad` — блокировка отправки отчетов о падениях.
  * `--disable-component-update` — блокировка несанкционированной загрузки компонентов.
  * `--disable-domain-reliability` — отключение телеметрии сетевых ошибок.
  * `--no-pings` — отключение протокола аудит-кликов по гиперссылкам.

### 2.5. Изоляция потоков (Stream Isolation) и очистка журналов
* На портах `SocksPort` и `HTTPTunnelPort` включены директивы `IsolateDestAddr` и `IsolateDestPort`. Каждое обращение к новому домену или порту строит независимый виртуальный контур, исключая корреляцию активности между открытыми вкладками или сервисами.
* Директива `SafeLogging 1` гарантирует скремблирование IP-адресов в служебных журналах Tor.
* Опциональный режим `Ephemeral` обеспечивает работу в оперативной памяти (`tmpfs`) без записи кэша консенсуса на накопитель.

---

## 3. Универсальная поддержка любых Linux-приложений

TuxProxy реализует трехуровневую систему адаптивного перехвата и изоляции сетевых вызовов:

### 3.1. Среда Electron / Chromium
* **Приложения:** Antigravity IDE, VS Code, Google Chrome, Brave, Discord, Slack, Obsidian, Spotify, Postman.
* **Механизм:** Автоматическое обнаружение через анализ бинарного файла и ELF-структуры (`leak.IsChromiumOrElectron`). Инжекция параметров ядра Chromium (`--proxy-server`, `--host-resolver-rules`, `--webrtc-ip-handling-policy`) в сочетании с переменными окружения POSIX.

### 3.2. Среда Java / JVM
* **Приложения:** IntelliJ IDEA, PyCharm, WebStorm, Android Studio, Eclipse, DBeaver, Ghidra, Gradle, Maven, standalone JAR.
* **Механизм:** Автоматическая инжекция системных свойств виртуальной машины Java через переменные:
  ```bash
  _JAVA_OPTIONS="-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=9050 -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=9080 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=9080"
  JAVA_TOOL_OPTIONS="-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=9050 -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=9080 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=9080"
  ```
  Обеспечивает сквозное туннелирование всех сетевых сокетов Java без изменения конфигурации IDE.

### 3.3. POSIX CLI-инструменты и скрипты
* **Инструменты:** `curl`, `wget`, `git`, `gh`, `python`, `pip`, `node`, `npm`, `yarn`, `pnpm`, `ruby`, `gem`, `go`, `cargo`, `docker-cli`.
* **Механизм:** Очистка системного окружения от посторонних прокси и инжекция защищенных переменных:
  ```bash
  ALL_PROXY="socks5h://127.0.0.1:9050"
  HTTP_PROXY="http://127.0.0.1:9080"
  HTTPS_PROXY="http://127.0.0.1:9080"
  FTP_PROXY="http://127.0.0.1:9080"
  RSYNC_PROXY="127.0.0.1:9080"
  NO_PROXY="localhost,127.0.0.1"
  ```

### 3.4. Системный перехват сокетов libc (Proxychains4 LD_PRELOAD)
* **Приложения:** Telegram Desktop, C/C++ бинарники, игры, сетевые демоны и утилиты, не читающие переменные окружения прокси.
* **Механизм:** Принудительный перехват системных вызовов `connect()`, `sendto()`, `getaddrinfo()` через динамический линковщик (`LD_PRELOAD`).
* **Конфигурация:** TuxProxy динамически генерирует уникальный файл `/tmp/tuxproxy-pc-*.conf` с политикой `strict_chain`, `proxy_dns` и `remote_dns_subnet 224`.
* **Активация:** Ключ командной строки `-p` / `--proxychains` или настройка `universal_app_mode = "proxychains"` в GUI.

---

## 4. Автоматическая интеграция с сессиями терминала (Shell Hook)

TuxProxy позволяет сделать так, чтобы **каждый запрос в терминале автоматически проходил через защищенный контур**:

### 4.1. Управление системным хуком
```bash
# Включить автоподключение для всех новых сессий терминала (~/.bashrc и ~/.zshrc)
tuxproxy hook enable

# Проверить текущий статус интеграции
tuxproxy hook status

# Отключить интеграцию и удалить хук из ~/.bashrc и ~/.zshrc
tuxproxy hook disable
```

### 4.2. Механика работы хука
При открытии новой вкладки терминала:
1. Оболочка выполняет блок `eval "$(tuxproxy hook init)"`.
2. Если локальный порт Tor (9050) не слушается, TuxProxy автоматически инициирует запуск постоянного фонового демона (`tuxproxy daemon`). Для предотвращения гонок нескольких вкладок используется анти-коллизионная проверка процессов.
3. Экспортируются переменные `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `_JAVA_OPTIONS`.
4. В строке приглашения терминала появляется статус-индикатор юрисдикции выхода:
   ```text
   [tuxproxy:US] user@host:~$
   ```

### 4.3. Встроенные команды управления внутри терминала
* **`tuxoff`** — моментально отключает проксирование в текущей вкладке терминала (снимает переменные и очищает `PS1`).
* **`tuxon`** — повторно активирует проксирование в текущей вкладке.
* **`tuxip`** — выводит текущий видимый внешний IP-адрес через SOCKS5-шлюз.

### 4.4. Ручной экспорт окружения
Для использования в автоматических скриптах CI/CD:
```bash
# Активировать переменные в текущей оболочке
eval "$(tuxproxy env)"

# Деактивировать переменные
eval "$(tuxproxy env --off)"

# Запустить изолированную интерактивную подоболочку
tuxproxy shell
```

---

## 5. Обход блокировок и Pluggable Transports

| Транспорт | Стек технологий | Принцип преодоления цензуры DPI |
| :--- | :--- | :--- |
| **Snowflake** *(По умолчанию)* | WebRTC + Google AMP Cache + Domain Fronting | Инициализация сессии (Rendezvous) скрывается внутри легитимных HTTPS-запросов к Google AMP Cache (`cdn.ampproject.org`) с фронтингом через `www.google.com`. Трафик маскируется под WebRTC видеозвонок. Высокая устойчивость к ТСПУ. |
| **obfs4 / Lyrebird** | Эллиптическая криптография, рандомизация энтропии | Устранение сигнатур TLS. Длина пакетов выравнивается псевдослучайным паддингом, превращая трафик в неструктурированный шум. |
| **WebTunnel** | HTTP/2 и HTTP/3 обратное проксирование | Маскирует сессию Tor под регулярный серфинг по HTTPS к веб-серверу с доверенным сертификатом. |
| **Custom Bridges** | Пользовательские строки | Поддержка ввода персональных мостов, полученных через Telegram-бот `@GetBridgesBot` или `bridges.torproject.org`. |
| **Direct (None)** | Прямой TLS Tor | Прямое подключение к публичным релеям сети без мостов (для зарубежных каналов). |

---

## 6. Контроль геолокации (Exit Nodes)

Сетевая модель Tor построена на трехслойной маршрутизации:
$$\text{Клиент [РФ / Сингапур]} \longrightarrow \text{Мост (Snowflake)} \longrightarrow \text{Промежуточный узел} \longrightarrow \text{Выходной узел [США]} \longrightarrow \text{Целевой сервер}$$

* Входной узел видит только адрес клиента (или WebRTC-прокси), но не знает адресата.
* Целевой сервер видит **исключительно IP-адрес выходного узла**.
* Физическое местоположение не влияет на внешний IP: для любого сервиса соединение исходит из юрисдикции выбранной страны.

### Строгая политика привязки (StrictNodes)
```text
ExitNodes {us}
StrictNodes 1
```
Флаг `StrictNodes 1` директивно запрещает Tor переключаться на узлы других стран при сбоях. При недоступности релеев выбранного региона соединение разрывается, предотвращая случайную утечку трафика через нежелательные страны.

---

## 7. Центр настроек (Web GUI Settings Studio)

Для настройки параметров утилиты запустите:
```bash
tuxproxy gui
# или: tuxproxy
```
Центр настроек открывается в браузере по адресу `http://127.0.0.1:9099`:

### Разделы панели конфигурации:
1. **🌍 Маршрутизация и Геолокация:**
   * Интерактивная сетка стран с флагами (США, Германия, Нидерланды, Швейцария, Канада, Великобритания, Швеция, Сингапур, Япония, Франция, Финляндия, Оптимальный).
   * Поле для ввода любого пользовательского двухбуквенного ISO-кода.
   * Переключатель строгой привязки (`StrictNodes`).
   * Список исключаемых стран и релеев (`ExcludeNodes`, например `{ru},{by},{cn}`).
   * Селектор количества входных узлов (`NumEntryGuards`, по умолчанию 1).
2. **🛡️ Обход блокировок (Мосты):**
   * Выбор транспорта: Snowflake, obfs4, WebTunnel, Custom Bridges, None.
   * Параметры Snowflake: Fronting Domain, AMP Cache URL.
   * Многострочное поле для вставки персональных мостов.
3. **💻 Интеграция с терминалом (Shell Hook):**
   * Кнопки активации и деактивации хука в `~/.bashrc` и `~/.zshrc`.
   * Опции автозапуска демона, индикатора `PS1` и поддержки `_JAVA_OPTIONS`.
   * Памятка встроенных команд терминала.
4. **🚀 Универсальная изоляция ПО:**
   * Выбор режима: `auto` (умный гибридный), `proxychains` (принудительный LD_PRELOAD), `env` (переменные POSIX), `electron` (песочница Chromium).
   * **Интерактивный генератор команд CLI** с быстрым копированием.
5. **🔌 Сетевые порты:**
   * Тонкая настройка портов SOCKS5h (9050), HTTP (9080), DNS (9053), ControlPort (9051).
6. **🔒 Zero-Leak OPSEC:**
   * Управление барьерами: отключение IPv6, блокировка DNS-утечек, подавление WebRTC, очистка логов Tor (`SafeLogging`), бесследный режим в RAM (`Ephemeral`).
7. **📁 Системные бинарники:**
   * Пути к исполняемым файлам `tor`, `snowflake-client`, `lyrebird`, `webtunnel-client`, `proxychains4`.
8. **Панель живой телеметрии:**
   * Мониторинг текущего видимого IP-адреса, страны, города, порта SOCKS5h и статуса хука.
   * Кнопка немедленного сетевого аудита (Egress Audit).
   * Кнопка ротации контура и смены IP (`Newnym`).
   * Кнопка сохранения параметров (`Ctrl+S`).

---

## 8. Полный справочник команд CLI

```text
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
    -h, --help                            Вывести техническую справку
    -v, --version                         Версия утилиты
```

### Примеры использования:

```bash
# 1. Запуск Antigravity IDE через шлюз США с защитой от DNS и WebRTC утечек
tuxproxy --open "antigravity-ide"

# 2. Запуск с принудительным переопределением юрисдикции на Германию и мостом Snowflake
tuxproxy --open "antigravity-ide" --country de --bridge snowflake

# 3. Запуск веб-браузера в изолированном контуре
tuxproxy open google-chrome-stable

# 4. Запуск среды разработки IntelliJ IDEA (автоинжекция _JAVA_OPTIONS)
tuxproxy open idea

# 5. Выполнение единичного защищенного сетевого запроса через консоль
tuxproxy open curl -s https://check.torproject.org/api/ip

# 6. Клонирование Git-репозитория через SOCKS5h шлюз
tuxproxy open git clone https://github.com/torproject/tor.git

# 7. Запуск приложения с принудительным перехватом сокетов через proxychains4
tuxproxy open --proxychains telegram-desktop

# 8. Активация глобального автопроксирования терминала
tuxproxy hook enable
```

---

## 9. Спецификация конфигурационного файла

Файл конфигурации расположен по пути: `~/.config/tuxproxy/config.json`.

```json
{
  "exit_country": "us",
  "strict_nodes": true,
  "exclude_nodes": "{ru},{by}",
  "num_entry_guards": 1,
  "bridge_type": "snowflake",
  "custom_bridges": [],
  "snowflake_url": "https://snowflake-broker.torproject.net/",
  "snowflake_front": "www.google.com",
  "snowflake_ampcache": "https://cdn.ampproject.org/",
  "socks_port": 9050,
  "http_port": 9080,
  "dns_port": 9053,
  "control_port": 9051,
  "disable_ipv6": true,
  "safe_logging": true,
  "prevent_webrtc_leak": true,
  "prevent_dns_leak": true,
  "force_proxychains": false,
  "ephemeral": false,
  "universal_app_mode": "auto",
  "java_proxy_support": true,
  "terminal_auto_hook": false,
  "shell_type": "auto",
  "terminal_auto_start_daemon": true,
  "show_prompt_indicator": true,
  "tor_binary_path": "/usr/bin/tor",
  "snowflake_path": "/usr/bin/snowflake-client",
  "lyrebird_path": "/home/djanki/.local/bin/lyrebird",
  "webtunnel_path": "/usr/local/bin/webtunnel-client",
  "proxychains_path": "/usr/bin/proxychains4"
}
```

---

## 10. Сборка и установка

### Сборка из исходного кода
```bash
git clone https://github.com/your-org/tuxproxy.git
cd tuxproxy
make
```

### Установка в систему
```bash
# Установка бинарника в ~/.local/bin/tuxproxy
make install

# Запуск тестов целостности
make test
```

### Системные зависимости Linux
Для полнофункциональной работы требуются пакеты:
```bash
# Arch Linux / Manjaro
sudo pacman -S tor proxychains-ng

# Debian / Ubuntu / Mint
sudo apt update && sudo apt install -y tor proxychains4
```
Клиент Snowflake и плагины обхода блокировок определяются автоматически в стандартных путях (`/usr/bin/snowflake-client`, `/usr/bin/lyrebird`, `~/.local/bin/lyrebird`).

---

## 11. Лицензия и гарантии безопасности

Проект распространяется под лицензией MIT. TuxProxy гарантирует отсутствие скрытых сетевых соединений, телеметрии и сторонних зависимостей. Все сетевые обращения ограничиваются локальным хостом (`127.0.0.1`) и сконфигурированным контуром Tor.
