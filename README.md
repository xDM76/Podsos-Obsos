# PodsosObsos — Universal Antigravity & agy CLI Patcher (macOS, Windows & Linux)

Универсальный инструмент для разблокировки Antigravity CLI (agy) и Antigravity 2.0 Desktop (language_server) на macOS (Apple Silicon arm64 / Intel x64), Windows (x64 / arm64) и Linux (x64 / aarch64).

Позволяет полноценно использовать Antigravity из России без VPN и без смены региона аккаунта Google.
Версия 1.4.0 построена на референсе confeden/Antigravity с использованием умного локального изолированного CONNECT-прокси и многоуровневого снятия ограничений.

---

## Архитектура и новшества версии 1.4.0

В отличие от классического статического пина в файле hosts (который часто зависал при быстрой ротации SNI IP или блокировках UDP DNS), версия 1.4.0 решает проблему на нескольких независимых уровнях:

1. **Изолированный сетевой канал (AG_LS_PROXY):**
   В скомпилированных Go-бинарниках agy и language_server системная переменная `https_proxy` переименована в `AG_LS_PROXY`. Это позволяет направить сетевой трафик Antigravity в локальный прокси без объявления системных переменных HTTP_PROXY / HTTPS_PROXY. Весь остальной трафик операционной системы (браузер, git, curl, brew, npm) работает в обычном режиме напрямую.

2. **Клиентский анлок региона (ineligible -> inexigible):**
   В бинарниках модифицированы строки десериализации protobuf-ответов сервера Google (`ineligible_tiers` -> `inexigible_tiers` и `ineligible` -> `inexigible`). При получении отказа от сервера с ошибкой 400 клиент игнорирует статус блокировки региона и открывает доступ к моделям.

3. **Машинный патчинг (Go Binary Gate):**
   На уровне инструкций процессора отключаются проверки eligibility в runtime (`hasValidAuth=true`, снятие eligibility screen). Поддерживаются архитектуры arm64 и x64. На macOS автоматически применяется ad-hoc переподпись через codesign и снимается карантин xattr.

4. **Локальная умная служба ag_proxy (127.0.0.1:53129):**
   - Перехватывает только запросы к шлюзам Google (`cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`).
   - Сторонний трафик (вход в аккаунт через Google OAuth, accounts.google.com, телеметрия) туннелируется напрямую без изменений.
   - Динамически резолвит рабочие SNI-прокси через HTTP/2 DoH узлов dns.dns-ai.ru (194.87.196.13, 45.151.102.219, 185.251.90.181).
   - Поддерживает подключение пользовательского upstream-прокси (HTTP / SOCKS5).
   - Watchdog логов клиента: при обнаружении ошибки 400 ("User location is not supported") автоматически штрафует упавший IP и мгновенно переключает трафик на следующий рабочий узел.

5. **Полная функция отката (Restore / Rollback в 1 клик):**
   Добавлена возможность полного возврата системы в исходное состояние одной командой (`--restore` / `--rollback`): восстановление оригинальных бинарников из бэкапов или in-place откат, остановка службы ag_proxy, удаление переменных из профилей оболочки/реестра и очистка DNS-пинов.

---

## Структура проекта

```text
PodsosObsos/
├── Запуск_Mac_PodsosObsos.command # Лаунчер для macOS
├── Запуск_WIN_PodsosObsos.bat     # Лаунчер для Windows
├── Запуск_Linux_PodsosObsos.sh    # Лаунчер для Linux
├── README.md                      # Документация проекта
│
└── PodsosoObsos/
    ├── common/                    # Общий кроссплатформенный движок
    │   ├── common.py              # Патчер бинарников (Go gates, ineligible, AG_LS_PROXY, revert)
    │   ├── ag_proxy.py            # Локальный HTTP CONNECT прокси и DoH роутер
    │   ├── settings.py            # Хранилище настроек (~/.podsoso_obsos/settings.json)
    │   ├── patch_ide.py           # Патчер JS-оболочки Electron для IDE
    │   └── podsoso_obsos.py       # Главный модуль CLI, меню и отката
    │
    ├── mac/                       # Платформенный адаптер macOS
    │   └── platform_mac.py        # codesign, quarantine, chflags, pkill, zshrc
    │
    ├── win/                       # Платформенный адаптер Windows
    │   └── platform_win.py        # HKCU\Environment, taskkill, setx, UAC
    │
    └── linux/                     # Платформенный адаптер Linux
        └── platform_linux.py      # bashrc/zshrc/profile, pkill, permissions
```

---

## Быстрый запуск

### 1. Запуск в один клик (рекомендуется)

#### macOS:
Дважды кликните по файлу **`Запуск_Mac_PodsosObsos.command`** либо выполните в терминале:
```bash
python3 PodsosoObsos/common/podsoso_obsos.py --all
```

#### Linux:
Запустите скрипт **`Запуск_Linux_PodsosObsos.sh`**:
```bash
chmod +x PodsosoObsos/Запуск_Linux_PodsosObsos.sh
./PodsosoObsos/Запуск_Linux_PodsosObsos.sh
```

#### Windows:
Дважды кликните по файлу **`Запуск_WIN_PodsosObsos.bat`** либо выполните в командной строке:
```cmd
python PodsosoObsos\common\podsoso_obsos.py --all
```

Пакетный запуск автоматически выполняет:
1. Полный патч бинарника `agy` CLI (машинный код + ineligible + AG_LS_PROXY).
2. Полный патч `language_server` (Antigravity 2.0 Desktop).
3. Персистентную установку переменных окружения `AG_LS_PROXY` и `CLOUD_CODE_URL`.
4. Запуск локальной службы `ag_proxy` в фоновом режиме на порту 53129.
5. Проверку сетевой связности со шлюзами Google API.

---

## Консольные команды CLI

Модуль `podsoso_obsos.py` поддерживает неинтерактивное управление через флаги:

- `--all`: Выполнить полный цикл анблока в один клик.
- `--restore`, `--rollback`: Выполнить полный откат всех изменений системы в исходное состояние в один клик.
- `--diagnostics`: Вывести подробный отчет о состоянии бинарников, службы прокси, переменных и сетевых маршрутов.
- `--proxy-start`: Запустить локальную службу ag_proxy в фоновом режиме.
- `--proxy-stop`: Остановить службу ag_proxy.
- `--proxy-status`: Проверить статус службы ag_proxy.
- `--custom-proxy <URL>`: Указать собственный upstream-прокси (например, `http://127.0.0.1:7890` или `socks5://127.0.0.1:10808`). Для возврата к автоматическому DoH SNI передайте пустое значение `""`.
- `--clean-env`: Очистить переменные окружения и остановить службу.
- `--agy-path <PATH>`: Указать нестандартный путь к бинарнику agy.
- `--manager-path <PATH>`: Указать нестандартный путь к language_server.

---

## Проверка работоспособности agy CLI

После выполнения пакетного запуска откройте новый терминал и выполните:

```bash
agy models
```

Вы увидите список доступных моделей:
- `gemini-3.8-flash-high`
- `claude-sonnet-4-6`
- `claude-opus-4-6-thinking`
- `gpt-oss-120b-medium`

Тестовый запрос к модели:
```bash
agy -p "Привет! Скажи, какая ты модель?"
```

---

## Меню программы

При интерактивном запуске без флагов доступно текстовое меню:

```text
  [1] ВСЕ В ОДИН КЛИК: Полный анблок (Патчи + Переменные + Служба + Тест)

  [2] Патч только agy CLI (код + ineligible + AG_LS_PROXY)
  [3] Патч только Antigravity 2.0 (language_server)
  [4] Управление службой ag_proxy (Запуск / Остановка / Перезапуск)
  [5] Настроить переменные окружения (AG_LS_PROXY и CLOUD_CODE_URL)
  [6] Настройка своего upstream-прокси (HTTP/SOCKS5 или DoH SNI)

  [7] ПОЛНЫЙ ОТКАТ В 1 КЛИК: вернуть систему в исходное состояние
  [8] Откат только бинарников из бэкапов
  [9] Очистить переменные окружения и остановить службу

  [10] Диагностика и проверка доступности моделей
  [0] Выход
```

---

## Откат изменений (Restore / Rollback)

Для полного возврата системы в исходное состояние достаточно одной команды:
```bash
python3 PodsosoObsos/common/podsoso_obsos.py --restore
```
Либо выберите пункт `[7]` в меню программы.

Процедура отката:
1. Останавливает фоновую службу `ag_proxy` и очищает PID-файл.
2. Восстанавливает оригинальные файлы `agy` и `language_server` из бэкапов `.agybak` (либо выполняет in-place откат байтов с переподписью `codesign`).
3. Удаляет переменные `AG_LS_PROXY` и `CLOUD_CODE_URL` из файлов профиля шелла (`.zshrc`, `.bashrc`, `.profile`) и системного реестра Windows.
4. Очищает любые DNS-записи анлокера из системного файла `hosts`.
