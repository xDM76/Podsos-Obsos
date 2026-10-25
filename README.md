# 🚀 PodsosoObsos — Universal Antigravity & agy CLI Patcher (macOS, Windows & Linux)

Универсальный инструмент для разблокировки **Antigravity CLI (`agy`)** и **Antigravity 2.0 (Desktop)** на **macOS** (Apple Silicon arm64 / Intel x64), **Windows** (x64 / arm64) и **Linux** (x64 / aarch64).

Позволяет полноценно использовать Antigravity из России **БЕЗ VPN и без смены региона аккаунта**.

---

## 📁 Структура проекта

Архитектура разделена на общее ядро в верхней папке и платформо-зависимые адаптеры в своих директориях:

```text
PodsosoObsos/
├── Запуск_Mac_PodsosObsos.command # 🍏 Запуск для macOS
├── Запуск_WIN_PodsosObsos.bat     # 🪟 Запуск для Windows
├── Запуск_Linux_PodsosObsos.sh    # 🐧 Запуск для Linux
├── README.md                      # Документация проекта
│
├── common/                        # 🧠 ОБЩЕЕ (для macOS, Windows и Linux)
│   ├── common.py                  # Сигнатуры гейтов Go, DoH/DNS резолвер, liveness, парсинг hosts
│   └── podsoso_obsos.py           # Главный скрипт, меню, пакетный запуск в 1 клик
│
├── mac/                           # 🍏 ЧАСТНОЕ ДЛЯ MACOS
│   └── platform_mac.py            # Codesign, xattr quarantine, chflags nouchg, pkill, dscacheutil, ~/.zshrc
│
├── win/                           # 🪟 ЧАСТНОЕ ДЛЯ WINDOWS
│   └── platform_win.py            # Реестр HKCU/HKLM Uninstall, taskkill, UAC RunAs, ipconfig /flushdns, setx
│
└── linux/                         # 🐧 ЧАСТНОЕ ДЛЯ LINUX
    └── platform_linux.py          # /etc/hosts, resolvectl/systemd-resolve, pkill, ~/.bashrc / ~/.zshrc / ~/.profile
```

---

## ⚡ Быстрый запуск

### На Linux:
Запустите скрипт **`Запуск_Linux_PodsosObsos.sh`**:
```bash
chmod +x Запуск_Linux_PodsosObsos.sh
./Запуск_Linux_PodsosObsos.sh
```

### На Windows:
Дважды кликните по файлу **`Запуск_WIN_PodsosObsos.bat`** на верхнем уровне папки `PodsosoObsos`.

> **💡 Примечание для Windows:** 
> Скрипт корректно находит бинарники `agy.exe` и `language_server.exe` как при обычном запуске, так и при запуске «От имени Администратора» (сканирует реестр и профили всех пользователей `C:\Users\*`). Если бинарник установлен в нестандартный каталог, скрипт предложит ввести путь вручную, либо его можно передать ключом:
> ```cmd
> python podsoso_obsos.py --agy-path "C:\Users\<user>\AppData\Local\agy\bin\agy.exe"
> ```

### На macOS:
Дважды кликните по файлу **`Запуск_Mac_PodsosObsos.command`** на верхнем уровне папки `PodsosoObsos`.

Либо через терминал:
```bash
python3 podsoso_obsos.py
```

---

## 🛠 Что делает PodsosoObsos

### 1. Бинарный машинный патчинг (Go Binary Gate)
- Снимает внутреннюю проверку региона аккаунта (`eligibility check`) в машинном коде `agy` и `language_server` (`Antigravity 2.0`).
- Поддерживает все архитектуры и компиляции: **x64 (AMD64 / Intel)** и **arm64 (Apple Silicon / Snapdragon)**.
- Поддерживает все актуальные версии и регистры (`w2`, `w4`, `w1`).
- Автоматически создает резервные копии `.agybak`.
- **На macOS**: автоматически накладывает ad-hoc подпись через `codesign --force --sign -` и снимает флаги `quarantine`/`uchg` (предотвращает ошибки `killed: 9` и «приложение повреждено»).
- **На Windows**: автоматически отслеживает и снимает файловые блокировки (file locks), завершая зависшие процессы через `taskkill` перед записью.

### 2. Сетевой анлокер (Работа БЕЗ VPN)
- Ищет живые SNI-прокси через современный **DoH HTTP/2** (`dns.dns-ai.ru`) и резервные резолверы (`geohide.ru`, `comss.one`).
- Сверяет ответы с эталонными адресами Google (`8.8.8.8` / `1.1.1.1`), чтобы исключить прямой маршрут.
- Проверяет доступность порта 443 (liveness probe).
- Записывает рабочие IP в системный файл `hosts`:
  - Linux: `/etc/hosts` (с безопасным запросом sudo при необходимости)
  - macOS: `/etc/hosts` (с безопасным запросом sudo при необходимости)
  - Windows: `C:\Windows\System32\drivers\etc\hosts` (с автоматическим UAC RunAs повышением при необходимости)
  - Для доменов:
    - `daily-cloudcode-pa.googleapis.com`
    - `generativelanguage.googleapis.com`
    - `cloudcode-pa.googleapis.com`
- Сбрасывает системный кэш DNS:
  - Linux: `resolvectl flush-caches`, `systemd-resolve`, `nscd`
  - macOS: `dscacheutil -flushcache`, `killall -HUP mDNSResponder`
  - Windows: `ipconfig /flushdns`
- Настраивает переменную `CLOUD_CODE_URL="https://daily-cloudcode-pa.googleapis.com"`:
  - Linux: добавляет в `~/.bashrc`, `~/.zshrc` и `~/.profile`
  - macOS: добавляет в `~/.zshrc`
  - Windows: сохраняет персистентно в системный реестр `HKCU\Environment` и применяет через `setx` для всех новых консолей

### 3. Безопасное пакетное выполнение в 1 клик (Пункт [1])
- Выполняет все первые 5 пунктов за одно нажатие.
- **Изоляция сбоев**: если какой-то пункт не проходит (например, бинарник еще не установлен или включен VPN), остальные шаги не ломаются и продолжают выполняться.
- **Итоговый отчёт**: в конце выводится наглядная сводка с цветовой индикацией (`✔ ПРОЙДЕН`, `⚠ ВНИМАНИЕ`, `✖ НЕ ПРОШЁЛ`) и точными рекомендациями по устранению любых возникших проблем.

### 4. Обратимость (Restore)
- Пункт меню `[6]` позволяет в любой момент вернуть оригинальные файлы из бэкапов.
- Пункт меню `[7]` начисто удаляет все записи анлокера из файла hosts.

---

## 📋 Меню программы

```text
  [1] 🌟 ВСЁ В ОДИН КЛИК: Выполнить все первые 5 пунктов (Безопасный режим + Отчёт)

  [2] Патч только agy CLI
  [3] Патч только Antigravity 2.0 (language_server)
  [4] Настроить / Обновить DNS-пин в hosts (Режим «Без VPN»)
  [5] Настроить CLOUD_CODE_URL для agy CLI

  [6] 🔄 Откат (RESTORE) бинарников из бэкапов
  [7] 🧹 Удалить DNS-пин из hosts (Вернуть стандартную сеть)

  [8] 🩺 Диагностика и статус сети
  [0] 🚪 Выход
```

---

> [!IMPORTANT]
> **Внимание при настройке режима «Без VPN»:**
> Анблок-DNS сервисы выдают подменяющие IP **только клиентам с российским IP**. 
> При запуске настройки DNS-пина **выключите VPN**. Если VPN включен, провайдеры вернут стандартные IP Google, и пин применен не будет.
