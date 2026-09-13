package gui

const DashboardHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TuxProxy — Центр конфигурации OPSEC и сетевой изоляции</title>
  <style>
    :root {
      --bg: #070a12;
      --panel-bg: #0d1322;
      --card-bg: #121a2f;
      --card-border: #1e293b;
      --border-focus: #3b82f6;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --accent-glow: rgba(37, 99, 235, 0.35);
      --success: #10b981;
      --success-glow: rgba(16, 185, 129, 0.25);
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --text-subtle: #64748b;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --radius: 8px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 20px; min-height: 100vh; line-height: 1.5; }
    .container { max-width: 1040px; margin: 0 auto; }

    /* Top Navigation Header */
    .header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 16px 20px; background: var(--panel-bg); border: 1px solid var(--card-border);
      border-radius: var(--radius); margin-bottom: 20px; flex-wrap: wrap; gap: 14px;
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-icon {
      background: linear-gradient(135deg, #1e3a8a, #2563eb); color: #fff;
      font-weight: 900; font-size: 16px; padding: 8px 12px; border-radius: 6px;
      letter-spacing: 1.5px; border: 1px solid rgba(255,255,255,0.15);
    }
    .brand-text h1 { font-size: 17px; font-weight: 800; letter-spacing: 0.5px; color: #fff; }
    .brand-text p { font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); }

    .header-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .status-badge {
      display: flex; align-items: center; gap: 8px; padding: 6px 12px;
      border-radius: 6px; font-size: 12px; font-weight: 700;
      background: #090e1a; border: 1px solid var(--card-border); font-family: var(--font-mono);
    }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; }
    .status-dot.active { background: var(--success); box-shadow: 0 0 8px var(--success); }
    .status-dot.booting { background: var(--warning); animation: pulse 1s infinite; }
    @keyframes pulse { 0% { opacity: 0.3; } 50% { opacity: 1; } 100% { opacity: 0.3; } }

    /* Action Buttons */
    .btn {
      display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
      border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;
      border: 1px solid transparent; transition: all 0.15s ease; user-select: none;
    }
    .btn-primary {
      background: var(--accent); color: #fff; border-color: #3b82f6;
      box-shadow: 0 2px 10px var(--accent-glow);
    }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-secondary { background: #1e293b; color: #e2e8f0; border-color: #334155; }
    .btn-secondary:hover { background: #334155; color: #fff; }
    .btn-success { background: #065f46; color: #34d399; border-color: #059669; }
    .btn-success:hover { background: #047857; color: #fff; }
    .btn-danger { background: #7f1d1d; color: #fca5a5; border-color: #991b1b; }
    .btn-danger:hover { background: #991b1b; color: #fff; }
    .btn-sm { padding: 5px 10px; font-size: 12px; }

    /* Live Telemetry Bar */
    .telemetry-bar {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px;
      margin-bottom: 20px;
    }
    .telem-box {
      background: var(--panel-bg); border: 1px solid var(--card-border); border-radius: var(--radius);
      padding: 12px 14px; display: flex; flex-direction: column; gap: 2px;
    }
    .telem-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-subtle); font-weight: 700; }
    .telem-val { font-size: 14px; font-weight: 700; color: #fff; font-family: var(--font-mono); word-break: break-all; }
    .telem-val.green { color: var(--success); }
    .telem-val.cyan { color: #38bdf8; }

    /* Tabs Layout */
    .tabs-nav {
      display: flex; gap: 4px; border-bottom: 1px solid var(--card-border);
      margin-bottom: 20px; overflow-x: auto; padding-bottom: 4px;
    }
    .tab-btn {
      background: transparent; border: 1px solid transparent; color: var(--text-muted);
      padding: 9px 16px; border-radius: 6px; font-size: 13px; font-weight: 600;
      cursor: pointer; transition: all 0.15s; white-space: nowrap; display: flex; align-items: center; gap: 8px;
    }
    .tab-btn:hover { color: #fff; background: rgba(255,255,255,0.03); }
    .tab-btn.active {
      color: #fff; background: var(--panel-bg); border-color: var(--card-border);
      border-bottom-color: var(--accent); border-bottom-width: 2px;
    }

    /* Tab Content Areas */
    .tab-pane { display: none; }
    .tab-pane.active { display: block; animation: fadeIn 0.2s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

    /* Section Cards */
    .card {
      background: var(--panel-bg); border: 1px solid var(--card-border);
      border-radius: var(--radius); padding: 20px; margin-bottom: 20px;
    }
    .card-header { margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--card-border); }
    .card-title { font-size: 15px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
    .card-desc { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

    /* Form Grids and Fields */
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 14px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    .form-label { font-size: 12px; font-weight: 600; color: var(--text); }
    .form-sublabel { font-size: 11px; color: var(--text-muted); }
    .form-control {
      background: #090e1a; border: 1px solid var(--card-border); border-radius: 6px;
      padding: 9px 12px; color: #fff; font-size: 13px; font-family: var(--font-mono); outline: none;
      transition: border-color 0.15s;
    }
    .form-control:focus { border-color: var(--border-focus); }
    textarea.form-control { resize: vertical; min-height: 80px; font-size: 12px; line-height: 1.4; }

    /* Custom Toggles */
    .toggle-row {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 14px; background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 6px; margin-bottom: 10px;
    }
    .toggle-info { display: flex; flex-direction: column; gap: 2px; }
    .toggle-title { font-size: 13px; font-weight: 600; color: #fff; }
    .toggle-desc { font-size: 12px; color: var(--text-muted); }

    .switch {
      position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0;
    }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
      background-color: #334155; transition: .2s; border-radius: 24px;
    }
    .slider:before {
      position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px;
      background-color: white; transition: .2s; border-radius: 50%;
    }
    input:checked + .slider { background-color: var(--accent); }
    input:checked + .slider:before { transform: translateX(20px); }

    /* Country Selection Grid */
    .country-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px;
      margin-bottom: 16px;
    }
    .country-card {
      background: var(--card-bg); border: 2px solid var(--card-border); border-radius: 6px;
      padding: 10px 8px; text-align: center; cursor: pointer; transition: all 0.15s;
    }
    .country-card:hover { border-color: #3b82f6; background: #1a2542; }
    .country-card.active { border-color: var(--accent); background: rgba(37, 99, 235, 0.15); box-shadow: 0 0 10px var(--accent-glow); }
    .country-flag { font-size: 24px; display: block; margin-bottom: 2px; }
    .country-title { font-size: 12px; font-weight: 700; color: #fff; }
    .country-tag { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }

    /* Bridge Cards */
    .bridge-grid { display: flex; flex-direction: column; gap: 10px; margin-bottom: 16px; }
    .bridge-item {
      display: flex; align-items: center; justify-content: space-between; padding: 12px 16px;
      background: var(--card-bg); border: 2px solid var(--card-border); border-radius: 6px;
      cursor: pointer; transition: all 0.15s;
    }
    .bridge-item:hover { border-color: #3b82f6; }
    .bridge-item.active { border-color: var(--accent); background: rgba(37, 99, 235, 0.15); box-shadow: 0 0 10px var(--accent-glow); }
    .bridge-meta h4 { font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
    .bridge-meta p { font-size: 12px; color: var(--text-muted); }
    .badge-rec {
      background: #065f46; color: #34d399; font-size: 10px; font-weight: 700;
      padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono);
    }

    /* CLI Generator Box */
    .cli-generator {
      background: #050811; border: 1px solid var(--card-border); border-radius: 6px;
      padding: 16px; margin-top: 10px;
    }
    .cli-cmd-row {
      display: flex; align-items: center; gap: 10px; background: #0b1120;
      border: 1px solid #1e293b; border-radius: 6px; padding: 8px 12px; margin-top: 8px;
    }
    .cli-cmd-text {
      flex: 1; font-family: var(--font-mono); font-size: 13px; color: #38bdf8;
      overflow-x: auto; white-space: nowrap;
    }

    /* Terminal Hook Status Box */
    .hook-status-box {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px; background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 6px; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;
    }

    /* Toast Notifications */
    #toast {
      position: fixed; bottom: 24px; right: 24px; background: #1e293b;
      color: #fff; border: 1px solid #334155; padding: 12px 18px; border-radius: 6px;
      font-size: 13px; font-weight: 600; box-shadow: 0 4px 16px rgba(0,0,0,0.5);
      opacity: 0; transform: translateY(10px); transition: all 0.2s; pointer-events: none; z-index: 1000;
    }
    #toast.show { opacity: 1; transform: translateY(0); }
    #toast.success { background: #064e3b; border-color: #059669; color: #6ee7b7; }
    #toast.error { background: #7f1d1d; border-color: #b91c1c; color: #fca5a5; }

    /* Code Block Notice */
    .code-notice {
      background: #080d1a; border-left: 3px solid var(--accent); padding: 10px 12px;
      border-radius: 0 6px 6px 0; font-size: 12px; color: var(--text-muted); margin: 10px 0;
      font-family: var(--font-mono);
    }
  </style>
</head>
<body>

<div class="container">
  <!-- Header -->
  <header class="header">
    <div class="brand">
      <div class="brand-icon">TUX</div>
      <div class="brand-text">
        <h1>TuxProxy // OPSEC Settings Studio</h1>
        <p>Строгий центр конфигурирования контура Tor и изоляции трафика</p>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-badge" id="statusBadge">
        <span class="status-dot" id="statusDot"></span>
        <span id="statusText">Опрос шлюза...</span>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="triggerTest()" title="Провести аудит сетевого шлюза">
        <span>Аудит</span>
      </button>
      <button class="btn btn-secondary btn-sm" onclick="triggerNewnym()" title="Получить новый выходной узел и IP">
        <span>Новый IP</span>
      </button>
      <button class="btn btn-primary" onclick="saveConfiguration()">
        <span>Сохранить настройки</span>
      </button>
    </div>
  </header>

  <!-- Live Telemetry -->
  <div class="telemetry-bar">
    <div class="telem-box">
      <span class="telem-label">Внешний IP (Exit IP)</span>
      <span class="telem-val cyan" id="telemIP">—</span>
    </div>
    <div class="telem-box">
      <span class="telem-label">Геолокация выхода</span>
      <span class="telem-val" id="telemGeo">—</span>
    </div>
    <div class="telem-box">
      <span class="telem-label">SOCKS5h шлюз</span>
      <span class="telem-val green" id="telemSocks">127.0.0.1:9050</span>
    </div>
    <div class="telem-box">
      <span class="telem-label">Интеграция с терминалом</span>
      <span class="telem-val" id="telemHook">Проверка...</span>
    </div>
  </div>

  <!-- Navigation Tabs -->
  <nav class="tabs-nav">
    <button class="tab-btn active" onclick="switchTab('routing')">🌍 Маршрутизация и Гео</button>
    <button class="tab-btn" onclick="switchTab('bridges')">🛡️ Обход блокировок (Мосты)</button>
    <button class="tab-btn" onclick="switchTab('terminal')">💻 Интеграция с терминалом</button>
    <button class="tab-btn" onclick="switchTab('universal')">🚀 Универсальная изоляция ПО</button>
    <button class="tab-btn" onclick="switchTab('ports')">🔌 Сетевые порты</button>
    <button class="tab-btn" onclick="switchTab('opsec')">🔒 Zero-Leak OPSEC</button>
    <button class="tab-btn" onclick="switchTab('binaries')">📁 Системные бинарники</button>
  </nav>

  <!-- TAB 1: Routing & Geolocation -->
  <div id="tab-routing" class="tab-pane active">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Страна выхода (Exit Node Geolocation)</h3>
        <p class="card-desc">Выберите целевую юрисдикцию, через которую будут выходить все сетевые запросы приложений</p>
      </div>

      <div class="country-grid" id="countryGrid">
        <div class="country-card" data-country="us" onclick="selectCountry('us')">
          <span class="country-flag">🇺🇸</span>
          <div class="country-title">США</div>
          <div class="country-tag">US</div>
        </div>
        <div class="country-card" data-country="de" onclick="selectCountry('de')">
          <span class="country-flag">🇩🇪</span>
          <div class="country-title">Германия</div>
          <div class="country-tag">DE</div>
        </div>
        <div class="country-card" data-country="nl" onclick="selectCountry('nl')">
          <span class="country-flag">🇳🇱</span>
          <div class="country-title">Нидерланды</div>
          <div class="country-tag">NL</div>
        </div>
        <div class="country-card" data-country="ch" onclick="selectCountry('ch')">
          <span class="country-flag">🇨🇭</span>
          <div class="country-title">Швейцария</div>
          <div class="country-tag">CH</div>
        </div>
        <div class="country-card" data-country="ca" onclick="selectCountry('ca')">
          <span class="country-flag">🇨🇦</span>
          <div class="country-title">Канада</div>
          <div class="country-tag">CA</div>
        </div>
        <div class="country-card" data-country="gb" onclick="selectCountry('gb')">
          <span class="country-flag">🇬🇧</span>
          <div class="country-title">Великобритания</div>
          <div class="country-tag">GB</div>
        </div>
        <div class="country-card" data-country="se" onclick="selectCountry('se')">
          <span class="country-flag">🇸🇪</span>
          <div class="country-title">Швеция</div>
          <div class="country-tag">SE</div>
        </div>
        <div class="country-card" data-country="sg" onclick="selectCountry('sg')">
          <span class="country-flag">🇸🇬</span>
          <div class="country-title">Сингапур</div>
          <div class="country-tag">SG</div>
        </div>
        <div class="country-card" data-country="jp" onclick="selectCountry('jp')">
          <span class="country-flag">🇯🇵</span>
          <div class="country-title">Япония</div>
          <div class="country-tag">JP</div>
        </div>
        <div class="country-card" data-country="fr" onclick="selectCountry('fr')">
          <span class="country-flag">🇫🇷</span>
          <div class="country-title">Франция</div>
          <div class="country-tag">FR</div>
        </div>
        <div class="country-card" data-country="fi" onclick="selectCountry('fi')">
          <span class="country-flag">🇫🇮</span>
          <div class="country-title">Финляндия</div>
          <div class="country-tag">FI</div>
        </div>
        <div class="country-card" data-country="any" onclick="selectCountry('any')">
          <span class="country-flag">🌐</span>
          <div class="country-title">Оптимальный</div>
          <div class="country-tag">ANY</div>
        </div>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Пользовательский ISO-код страны</label>
          <input type="text" class="form-control" id="exit_country" placeholder="us, de, nl или any" maxlength="8">
          <span class="form-sublabel">Пример: us, de, fi, se, ch (или оставьте пустым для автовыбора)</span>
        </div>
        <div class="form-group">
          <label class="form-label">Исключаемые страны и релеи (ExcludeNodes)</label>
          <input type="text" class="form-control" id="exclude_nodes" placeholder="{ru},{by},{cn},{ir}">
          <span class="form-sublabel">Узлы, через которые маршрутизация строго запрещена</span>
        </div>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Строгая привязка узлов (StrictNodes 1)</div>
          <div class="toggle-desc">Запретить построение контура через иные страны, если релеи выбранной юрисдикции недоступны</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="strict_nodes">
          <span class="slider"></span>
        </label>
      </div>

      <div class="form-group" style="margin-top: 10px;">
        <label class="form-label">Количество входных узлов (NumEntryGuards)</label>
        <select class="form-control" id="num_entry_guards">
          <option value="1">1 узел (Максимальная защита от корреляционных тайминг-атак — Рекомендуется)</option>
          <option value="2">2 узла (Баланс отказоустойчивости и приватности)</option>
          <option value="3">3 узла (Максимальная надежность при нестабильной сети)</option>
        </select>
      </div>
    </div>
  </div>

  <!-- TAB 2: Bridges -->
  <div id="tab-bridges" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Обход блокировок и Pluggable Transports</h3>
        <p class="card-desc">Технологии маскировки трафика для преодоления глубокой фильтрации пакетов (DPI)</p>
      </div>

      <div class="bridge-grid">
        <div class="bridge-item" data-bridge="snowflake" onclick="selectBridge('snowflake')">
          <div class="bridge-meta">
            <h4>Snowflake <span class="badge-rec">Рекомендуется для РФ</span></h4>
            <p>Маскировка под WebRTC видеозвонок с сигнальным фронтингом через Google AMP Cache</p>
          </div>
          <input type="radio" name="bridge_radio" value="snowflake">
        </div>

        <div class="bridge-item" data-bridge="obfs4" onclick="selectBridge('obfs4')">
          <div class="bridge-meta">
            <h4>obfs4 / Lyrebird</h4>
            <p>Криптографическая обфускация трафика с рандомизацией сигнатур и энтропии пакетов</p>
          </div>
          <input type="radio" name="bridge_radio" value="obfs4">
        </div>

        <div class="bridge-item" data-bridge="webtunnel" onclick="selectBridge('webtunnel')">
          <div class="bridge-meta">
            <h4>WebTunnel</h4>
            <p>Полная маскировка трафика Tor под обычный HTTPS веб-сервер с валидными сертификатами</p>
          </div>
          <input type="radio" name="bridge_radio" value="webtunnel">
        </div>

        <div class="bridge-item" data-bridge="custom" onclick="selectBridge('custom')">
          <div class="bridge-meta">
            <h4>Пользовательские мосты (Custom Bridges)</h4>
            <p>Использование собственных приватных строк мостов Tor, полученных через bridges.torproject.org</p>
          </div>
          <input type="radio" name="bridge_radio" value="custom">
        </div>

        <div class="bridge-item" data-bridge="none" onclick="selectBridge('none')">
          <div class="bridge-meta">
            <h4>Прямое подключение (Без мостов)</h4>
            <p>Прямое соединение со стандартными релеями Tor (не работает в сетях с активной блокировкой Tor)</p>
          </div>
          <input type="radio" name="bridge_radio" value="none">
        </div>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Snowflake Fronting Domain</label>
          <input type="text" class="form-control" id="snowflake_front" placeholder="www.google.com">
        </div>
        <div class="form-group">
          <label class="form-label">Snowflake AMP Cache URL</label>
          <input type="text" class="form-control" id="snowflake_ampcache" placeholder="https://cdn.ampproject.org/">
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Пользовательские строки мостов (Каждая строка с новой линии)</label>
        <textarea class="form-control" id="custom_bridges" placeholder="obfs4 192.0.2.1:443 756E6114... cert=... iat-mode=0&#10;webtunnel 192.0.2.2:443 ... url=..."></textarea>
      </div>
    </div>
  </div>

  <!-- TAB 3: Terminal Hook -->
  <div id="tab-terminal" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Автоматическая интеграция с сессиями терминала (Shell Hook)</h3>
        <p class="card-desc">Позволяет автоматически маршрутизировать любые сетевые запросы из командной строки (curl, git, python, pip, npm, apt) через TuxProxy без ручной настройки</p>
      </div>

      <div class="hook-status-box">
        <div>
          <div style="font-weight: 700; font-size: 14px; margin-bottom: 2px;">Статус интеграции с оболочкой:</div>
          <div style="font-size: 12px; color: var(--text-muted);" id="hookStatusDetail">Определение статуса ~/.bashrc и ~/.zshrc...</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-success btn-sm" onclick="setHook(true)">Активировать хук в ~/.bashrc</button>
          <button class="btn btn-danger btn-sm" onclick="setHook(false)">Отключить хук</button>
        </div>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Автоподключение при открытии терминала (TerminalAutoHook)</div>
          <div class="toggle-desc">Автоматически экспортировать переменные ALL_PROXY, HTTP_PROXY и HTTPS_PROXY в каждую новую сессию</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="terminal_auto_hook">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Автозапуск фонового демона Tor (TerminalAutoStartDaemon)</div>
          <div class="toggle-desc">Если при открытии консоли служба TuxProxy не запущена, автоматически стартовать её в фоне</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="terminal_auto_start_daemon">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Индикатор прокси в командной строке (ShowPromptIndicator)</div>
          <div class="toggle-desc">Отображать статусное обозначение [tuxproxy:US] перед строкой ввода команд в терминале</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="show_prompt_indicator">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Проксирование Java / JVM приложений (_JAVA_OPTIONS)</div>
          <div class="toggle-desc">Автоматически проксировать Java, Gradle, Maven, IntelliJ IDEA и JVM утилиты в сессии</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="java_proxy_support">
          <span class="slider"></span>
        </label>
      </div>

      <div class="card-header" style="margin-top: 20px;">
        <h4 style="font-size: 13px; font-weight: 700; color: #fff;">Встроенные команды управления в терминале:</h4>
      </div>

      <div class="code-notice">
        • <b>tuxoff</b>   — временно отключить проксирование в текущем окне терминала<br>
        • <b>tuxon</b>    — повторно включить проксирование в текущем терминале<br>
        • <b>tuxip</b>    — проверить текущий внешний IP-адрес и факт работы через Tor<br>
        • <b>eval "$(tuxproxy env)"</b>       — экспортировать переменные проксирования вручную<br>
        • <b>eval "$(tuxproxy env --off)"</b> — снять все переменные проксирования
      </div>
    </div>
  </div>

  <!-- TAB 4: Universal App Sandbox -->
  <div id="tab-universal" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Универсальная изоляция любых приложений</h3>
        <p class="card-desc">TuxProxy спроектирован для запуска любых процессов Linux. Основной запуск приложений выполняется строго через CLI-терминал для обеспечения полной изоляции сигнатур и дескрипторов.</p>
      </div>

      <div class="form-group">
        <label class="form-label">Режим универсального проксирования (UniversalAppMode)</label>
        <select class="form-control" id="universal_app_mode" onchange="updateCliGen()">
          <option value="auto">auto — Автоматический гибридный режим (Electron флаги + JVM свойства + переменные окружения)</option>
          <option value="proxychains">proxychains — Принудительный перехват всех сокетов libc через proxychains4 (LD_PRELOAD для любых ELF)</option>
          <option value="env">env — Изоляция через переменные окружения (ALL_PROXY=socks5h://, HTTP_PROXY, HTTPS_PROXY)</option>
          <option value="electron">electron — Принудительный режим песочницы Chromium / Electron (анти-WebRTC и хост-резолвер)</option>
        </select>
        <span class="form-sublabel">Режим "auto" самостоятельно определяет класс запускаемого ПО (Chromium, Java или системный бинарник)</span>
      </div>

      <div class="cli-generator">
        <div style="font-weight: 700; font-size: 13px; color: #fff; margin-bottom: 6px;">Интерактивный генератор командной строки для запуска:</div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
          Введите имя или команду вашей программы, чтобы сформировать готовую команду запуска через TuxProxy:
        </p>
        <div style="display: flex; gap: 8px;">
          <input type="text" class="form-control" id="cliInput" value="antigravity-ide" placeholder="например: antigravity-ide, firefox, curl, telegram-desktop" oninput="updateCliGen()">
          <button class="btn btn-secondary btn-sm" onclick="setCliPreset('antigravity-ide')">Antigravity</button>
          <button class="btn btn-secondary btn-sm" onclick="setCliPreset('firefox')">Firefox</button>
          <button class="btn btn-secondary btn-sm" onclick="setCliPreset('curl -s https://check.torproject.org/api/ip')">Curl</button>
          <button class="btn btn-secondary btn-sm" onclick="setCliPreset('telegram-desktop')">Telegram</button>
        </div>

        <div class="cli-cmd-row">
          <span class="cli-cmd-text" id="cliGeneratedCmd">tuxproxy --open "antigravity-ide"</span>
          <button class="btn btn-primary btn-sm" onclick="copyCliCmd()">Скопировать</button>
        </div>
      </div>

      <div class="code-notice" style="margin-top: 14px;">
        💡 <b>Принцип безопасности:</b> В графическом интерфейсе приложения намеренно не запускаются напрямую, так как веб-браузер накладывает ограничения безопасности (sandbox, дескрипторы сокетов). Запуск через команду <code>tuxproxy --open "&lt;приложение&gt;"</code> обеспечивает 100% перехват сетевых вызовов, гарантирует отсутствие DNS-утечек и корректно перенаправляет сигналы SIGINT/SIGTERM.
      </div>
    </div>
  </div>

  <!-- TAB 5: Network Ports -->
  <div id="tab-ports" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Локальные сетевые слушатели и порты</h3>
        <p class="card-desc">Конфигурация локальных портов, открываемых службой TuxProxy для приёма трафика</p>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">SOCKS5h Порт (SocksPort)</label>
          <input type="number" class="form-control" id="socks_port" value="9050">
          <span class="form-sublabel">Основной порт с удалённым резолвингом DNS (по умолчанию: 9050)</span>
        </div>
        <div class="form-group">
          <label class="form-label">HTTP CONNECT Tunnel Порт (HTTPPort)</label>
          <input type="number" class="form-control" id="http_port" value="9080">
          <span class="form-sublabel">Порт для ПО, поддерживающего только стандартный HTTP/HTTPS прокси</span>
        </div>
        <div class="form-group">
          <label class="form-label">DNS Резолвер Tor (DNSPort)</label>
          <input type="number" class="form-control" id="dns_port" value="9053">
          <span class="form-sublabel">Локальный DNS-сервер Tor для перенаправления UDP-запросов резолва</span>
        </div>
        <div class="form-group">
          <label class="form-label">Порт управления Tor (ControlPort)</label>
          <input type="number" class="form-control" id="control_port" value="9051">
          <span class="form-sublabel">Используется утилитой для отправки сигнала смены личности (SIGNAL NEWNYM)</span>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 6: Zero-Leak OPSEC -->
  <div id="tab-opsec" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Параметры безопасности и защита от утечек (Zero-Leak OPSEC)</h3>
        <p class="card-desc">Строгие барьеры предотвращения утечек реального IP-адреса, системных идентификаторов и метаданных</p>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Полное отключение IPv6 (ClientUseIPv6 0)</div>
          <div class="toggle-desc">Блокирует утечки реального адреса через dual-stack IPv6 маршрутизацию провайдера</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="disable_ipv6">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Предотвращение утечек DNS (Remote DNS Resolution)</div>
          <div class="toggle-desc">Запрещает обращение к системному DNS через socks5h и host-resolver-rules="MAP * ~NOTFOUND"</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="prevent_dns_leak">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Подавление WebRTC UDP (PreventWebRTCLeak)</div>
          <div class="toggle-desc">Отключает прямой не-проксированный WebRTC UDP трафик, исключая раскрытие локального IP в браузерах</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="prevent_webrtc_leak">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Безопасное логирование без IP (SafeLogging 1)</div>
          <div class="toggle-desc">Заменяет все IP-адреса и сетевые идентификаторы в служебных журналах Tor на [scrubbed]</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="safe_logging">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Принудительный proxychains4 (ForceProxychains)</div>
          <div class="toggle-desc">Перехватывать вызовы connect() и getaddrinfo() через LD_PRELOAD для всех запускаемых программ</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="force_proxychains">
          <span class="slider"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div class="toggle-info">
          <div class="toggle-title">Бесследный режим в RAM (Ephemeral tmpfs)</div>
          <div class="toggle-desc">Размещать временную директорию Tor исключительно в оперативной памяти без следов на диске</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="ephemeral">
          <span class="slider"></span>
        </label>
      </div>
    </div>
  </div>

  <!-- TAB 7: System Binaries -->
  <div id="tab-binaries" class="tab-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Системные бинарные файлы и транспорты</h3>
        <p class="card-desc">Пути к установленным в Linux исполняемым файлам (определяются автоматически, можно переопределить)</p>
      </div>

      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Бинарник Tor</label>
          <input type="text" class="form-control" id="tor_binary_path">
        </div>
        <div class="form-group">
          <label class="form-label">Snowflake Client</label>
          <input type="text" class="form-control" id="snowflake_path">
        </div>
        <div class="form-group">
          <label class="form-label">Lyrebird (obfs4)</label>
          <input type="text" class="form-control" id="lyrebird_path">
        </div>
        <div class="form-group">
          <label class="form-label">WebTunnel Client</label>
          <input type="text" class="form-control" id="webtunnel_path">
        </div>
        <div class="form-group">
          <label class="form-label">Proxychains4</label>
          <input type="text" class="form-control" id="proxychains_path">
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 10px;">
        <button class="btn btn-secondary btn-sm" onclick="resetToDefaults()">Сбросить к эталонным настройкам</button>
      </div>
    </div>
  </div>
</div>

<div id="toast">Настройки сохранены</div>

<script>
  let currentConfig = {};

  // Tab switching
  function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    
    event.currentTarget.classList.add('active');
    const target = document.getElementById('tab-' + tabId);
    if (target) target.classList.add('active');
  }

  // Country selection
  function selectCountry(code) {
    document.querySelectorAll('.country-card').forEach(c => c.classList.remove('active'));
    const target = document.querySelector('.country-card[data-country="' + code + '"]');
    if (target) target.classList.add('active');
    document.getElementById('exit_country').value = code;
    updateCliGen();
  }

  // Bridge selection
  function selectBridge(bridge) {
    document.querySelectorAll('.bridge-item').forEach(b => b.classList.remove('active'));
    const target = document.querySelector('.bridge-item[data-bridge="' + bridge + '"]');
    if (target) {
      target.classList.add('active');
      const radio = target.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    }
  }

  // CLI Generator
  function updateCliGen() {
    const input = document.getElementById('cliInput').value.trim() || 'antigravity-ide';
    const country = document.getElementById('exit_country').value.trim();
    const mode = document.getElementById('universal_app_mode').value;
    
    let cmd = 'tuxproxy --open "' + input + '"';
    if (country && country !== 'any') {
      cmd += ' --country ' + country;
    }
    if (mode === 'proxychains') {
      cmd += ' --proxychains';
    }
    document.getElementById('cliGeneratedCmd').innerText = cmd;
  }

  function setCliPreset(preset) {
    document.getElementById('cliInput').value = preset;
    updateCliGen();
  }

  function copyCliCmd() {
    const cmd = document.getElementById('cliGeneratedCmd').innerText;
    navigator.clipboard.writeText(cmd).then(() => {
      showToast('Команда скопирована в буфер обмена: ' + cmd, 'success');
    }).catch(() => {
      showToast('Скопируйте команду вручную: ' + cmd, 'error');
    });
  }

  // Show Toast
  function showToast(msg, type = 'success') {
    const toast = document.getElementById('toast');
    toast.innerText = msg;
    toast.className = type + ' show';
    setTimeout(() => {
      toast.className = '';
    }, 3200);
  }

  // Load Config
  async function loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      currentConfig = await res.json();

      // Routing
      document.getElementById('exit_country').value = currentConfig.exit_country || 'any';
      selectCountry(currentConfig.exit_country || 'any');
      document.getElementById('exclude_nodes').value = currentConfig.exclude_nodes || '';
      document.getElementById('strict_nodes').checked = !!currentConfig.strict_nodes;
      document.getElementById('num_entry_guards').value = currentConfig.num_entry_guards || 1;

      // Bridges
      selectBridge(currentConfig.bridge_type || 'snowflake');
      document.getElementById('snowflake_front').value = currentConfig.snowflake_front || '';
      document.getElementById('snowflake_ampcache').value = currentConfig.snowflake_ampcache || '';
      document.getElementById('custom_bridges').value = (currentConfig.custom_bridges || []).join('\n');

      // Terminal Hook
      document.getElementById('terminal_auto_hook').checked = !!currentConfig.terminal_auto_hook;
      document.getElementById('terminal_auto_start_daemon').checked = !!currentConfig.terminal_auto_start_daemon;
      document.getElementById('show_prompt_indicator').checked = !!currentConfig.show_prompt_indicator;
      document.getElementById('java_proxy_support').checked = !!currentConfig.java_proxy_support;

      // Universal Mode
      document.getElementById('universal_app_mode').value = currentConfig.universal_app_mode || 'auto';

      // Ports
      document.getElementById('socks_port').value = currentConfig.socks_port || 9050;
      document.getElementById('http_port').value = currentConfig.http_port || 9080;
      document.getElementById('dns_port').value = currentConfig.dns_port || 9053;
      document.getElementById('control_port').value = currentConfig.control_port || 9051;

      // OPSEC
      document.getElementById('disable_ipv6').checked = !!currentConfig.disable_ipv6;
      document.getElementById('prevent_dns_leak').checked = !!currentConfig.prevent_dns_leak;
      document.getElementById('prevent_webrtc_leak').checked = !!currentConfig.prevent_webrtc_leak;
      document.getElementById('safe_logging').checked = !!currentConfig.safe_logging;
      document.getElementById('force_proxychains').checked = !!currentConfig.force_proxychains;
      document.getElementById('ephemeral').checked = !!currentConfig.ephemeral;

      // Paths
      document.getElementById('tor_binary_path').value = currentConfig.tor_binary_path || '';
      document.getElementById('snowflake_path').value = currentConfig.snowflake_path || '';
      document.getElementById('lyrebird_path').value = currentConfig.lyrebird_path || '';
      document.getElementById('webtunnel_path').value = currentConfig.webtunnel_path || '';
      document.getElementById('proxychains_path').value = currentConfig.proxychains_path || '';

      updateCliGen();
    } catch (e) {
      console.error('Failed to load config:', e);
    }
  }

  // Save Config
  async function saveConfiguration() {
    const selectedBridge = document.querySelector('input[name="bridge_radio"]:checked');
    const customBridgesRaw = document.getElementById('custom_bridges').value.split('\n').map(s => s.trim()).filter(Boolean);

    const payload = {
      exit_country: document.getElementById('exit_country').value.trim().toLowerCase(),
      strict_nodes: document.getElementById('strict_nodes').checked,
      exclude_nodes: document.getElementById('exclude_nodes').value.trim(),
      num_entry_guards: parseInt(document.getElementById('num_entry_guards').value, 10) || 1,

      bridge_type: selectedBridge ? selectedBridge.value : 'snowflake',
      snowflake_front: document.getElementById('snowflake_front').value.trim(),
      snowflake_ampcache: document.getElementById('snowflake_ampcache').value.trim(),
      custom_bridges: customBridgesRaw,

      terminal_auto_hook: document.getElementById('terminal_auto_hook').checked,
      terminal_auto_start_daemon: document.getElementById('terminal_auto_start_daemon').checked,
      show_prompt_indicator: document.getElementById('show_prompt_indicator').checked,
      java_proxy_support: document.getElementById('java_proxy_support').checked,

      universal_app_mode: document.getElementById('universal_app_mode').value,

      socks_port: parseInt(document.getElementById('socks_port').value, 10) || 9050,
      http_port: parseInt(document.getElementById('http_port').value, 10) || 9080,
      dns_port: parseInt(document.getElementById('dns_port').value, 10) || 9053,
      control_port: parseInt(document.getElementById('control_port').value, 10) || 9051,

      disable_ipv6: document.getElementById('disable_ipv6').checked,
      prevent_dns_leak: document.getElementById('prevent_dns_leak').checked,
      prevent_webrtc_leak: document.getElementById('prevent_webrtc_leak').checked,
      safe_logging: document.getElementById('safe_logging').checked,
      force_proxychains: document.getElementById('force_proxychains').checked,
      ephemeral: document.getElementById('ephemeral').checked,

      tor_binary_path: document.getElementById('tor_binary_path').value.trim(),
      snowflake_path: document.getElementById('snowflake_path').value.trim(),
      lyrebird_path: document.getElementById('lyrebird_path').value.trim(),
      webtunnel_path: document.getElementById('webtunnel_path').value.trim(),
      proxychains_path: document.getElementById('proxychains_path').value.trim(),
    };

    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        showToast('Параметры безопасности TuxProxy успешно сохранены!', 'success');
        fetchStatus();
      } else {
        showToast('Ошибка сохранения конфигурации', 'error');
      }
    } catch (e) {
      showToast('Сбой обращения к API: ' + e.message, 'error');
    }
  }

  // Hook enable/disable
  async function setHook(enable) {
    try {
      const endpoint = enable ? '/api/hook/enable' : '/api/hook/disable';
      const res = await fetch(endpoint, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast(enable ? 'Интеграция с оболочкой успешно активирована' : 'Хук оболочки удален', 'success');
        document.getElementById('terminal_auto_hook').checked = enable;
        fetchStatus();
      } else {
        showToast('Ошибка изменения хука: ' + (data.error || 'неизвестно'), 'error');
      }
    } catch (e) {
      showToast('Сбой сети: ' + e.message, 'error');
    }
  }

  // Audit test
  async function triggerTest() {
    showToast('Выполняется аудит контура и проверка отсутствия утечек...', 'success');
    try {
      const res = await fetch('/api/test', { method: 'POST' });
      const data = await res.json();
      if (data.ip) {
        showToast('Аудит успешен! Внешний IP: ' + data.ip + ' (' + data.country + ')', 'success');
        fetchStatus();
      } else {
        showToast('Результат аудита: ' + (data.error || 'Ожидание построения туннеля'), 'error');
      }
    } catch (e) {
      showToast('Сбой проверки: ' + e.message, 'error');
    }
  }

  // Newnym rotate IP
  async function triggerNewnym() {
    showToast('Отправлен сигнал ротации контура (SIGNAL NEWNYM)...', 'success');
    try {
      const res = await fetch('/api/newnym', { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast('Новая цепочка Tor строится, смена IP...', 'success');
        setTimeout(fetchStatus, 2500);
      } else {
        showToast('Ошибка: ' + (data.error || 'Служба Tor не отвечает'), 'error');
      }
    } catch (e) {
      showToast('Сбой сети: ' + e.message, 'error');
    }
  }

  // Reset to Defaults
  async function resetToDefaults() {
    if (!confirm('Вы уверены, что хотите сбросить все параметры к рекомендованным эталонным значениям OPSEC?')) return;
    try {
      const res = await fetch('/api/config/reset', { method: 'POST' });
      if (res.ok) {
        showToast('Конфигурация сброшена к эталонным значениям', 'success');
        loadConfig();
      }
    } catch (e) {
      showToast('Ошибка сброса: ' + e.message, 'error');
    }
  }

  // Poll status
  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) return;
      const data = await res.json();

      const dot = document.getElementById('statusDot');
      const text = document.getElementById('statusText');
      
      if (data.active) {
        dot.className = 'status-dot active';
        text.innerText = 'АКТИВЕН [127.0.0.1:' + data.port + ']';
      } else if (data.bootstrapping) {
        dot.className = 'status-dot booting';
        text.innerText = 'БУТСТРАП: ' + (data.percent || 0) + '%';
      } else {
        dot.className = 'status-dot';
        text.innerText = 'ОЖИДАНИЕ ЗАПУСКА CLI';
      }

      document.getElementById('telemIP').innerText = data.ip || 'Защищен (скрыт)';
      document.getElementById('telemGeo').innerText = data.country ? (data.country + (data.city ? ' · ' + data.city : '')) : 'Узел Tor активен';
      document.getElementById('telemSocks').innerText = '127.0.0.1:' + (data.port || 9050);
      
      const hookDetail = document.getElementById('hookStatusDetail');
      const telemHook = document.getElementById('telemHook');
      if (data.hook_installed) {
        telemHook.innerText = 'ВКЛЮЧЕН [~/.bashrc]';
        telemHook.className = 'telem-val green';
        if (hookDetail) hookDetail.innerText = 'Хук установлен в файлах инициализации оболочки (~/.bashrc / ~/.zshrc)';
      } else {
        telemHook.innerText = 'ОТКЛЮЧЕН';
        telemHook.className = 'telem-val';
        if (hookDetail) hookDetail.innerText = 'Интеграция с оболочкой отключена (команды терминала идут напрямую)';
      }
    } catch (e) {
      // offline or closing
    }
  }

  // Keyboard shortcut Ctrl+S
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      saveConfiguration();
    }
  });

  // Init
  loadConfig();
  fetchStatus();
  setInterval(fetchStatus, 3000);
</script>
</body>
</html>
`
