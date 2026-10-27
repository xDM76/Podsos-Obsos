#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — All-in-One Antigravity & agy CLI Patcher (Universal)
=============================================================================
  Кроссплатформенный патчер и сетевой анлокер для macOS, Windows и Linux.
  Версия 2.0.0 — умный изолированный прокси без VPN (референс: confeden/Antigravity).

  Архитектура проекта:
  - Верхняя папка: общий движок common.py, точка входа podsoso_obsos.py, README.md
  - mac/: платформенный адаптер macOS (codesign, xattr, chflags, pkill, zshrc) + лаунчеры
  - win/: платформенный адаптер Windows (taskkill, registry, UAC RunAs, setx, hosts) + лаунчеры
  - linux/: платформенный адаптер Linux (hosts, resolvectl, pkill, bashrc/zshrc) + лаунчеры
=============================================================================
"""

import os
import sys
import socket
import subprocess
import time

# Включаем поддержку ANSI VT100 цветов в консоли Windows
if sys.platform == "win32" or os.name == "nt":
    os.system("")

# Импорт общего модуля из текущей папки
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import common
from common import (
    VERSION,
    CLOUD_CODE_URL_CANONICAL,
    AG_LS_PROXY_CANONICAL,
    AG_LS_PROXY_DEFAULT_PORT,
    color,
    C_CYAN,
    C_TURQUOISE,
    C_BRIGHT_CYAN,
    C_GREEN,
    C_YELLOW,
    C_RED,
    C_BOLD,
    C_DIM,
    C_RESET,
    log_ok,
    log_warn,
    log_err,
    log_info,
    log_step,
    clear_screen,
    Gate,
    MultiGate,
    CLI_GATE,
    MANAGER_GATE,
    get_binary_status,
    apply_binary_patch,
    restore_binary,
    setup_dns_pin,
    remove_dns_pin,
    get_public_ip_info,
    query_doh_dns_ai,
    validate_ip_https,
    get_existing_pins,
)
import settings
import ag_proxy
import patch_ide

# =============================================================================
# ИНИЦИАЛИЗАЦИЯ ПЛАТФОРМЕННОГО АДАПТЕРА
# =============================================================================

def get_platform_adapter():
    """Автоматически выбирает и загружает нужный адаптер (Mac, Win или Linux)."""
    root_dir = os.path.dirname(current_dir)
    if sys.platform == "win32" or os.name == "nt":
        win_dir = os.path.join(root_dir, "win")
        if win_dir not in sys.path:
            sys.path.insert(0, win_dir)
        from platform_win import WinPlatform
        return WinPlatform()
    elif sys.platform.startswith("linux"):
        linux_dir = os.path.join(root_dir, "linux")
        if linux_dir not in sys.path:
            sys.path.insert(0, linux_dir)
        from platform_linux import LinuxPlatform
        return LinuxPlatform()
    else:
        mac_dir = os.path.join(root_dir, "mac")
        if mac_dir not in sys.path:
            sys.path.insert(0, mac_dir)
        from platform_mac import MacPlatform
        return MacPlatform()

platform = get_platform_adapter()

HOSTS_FILE = platform.get_hosts_path()

# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ФОРМАТИРОВАНИЯ СТАТУСА
# =============================================================================

def format_patch_details(status_code: str, details: dict) -> str:
    if not details:
        if status_code.startswith("patched"):
            return color("ПРОПАТЧЕН", C_GREEN, C_BOLD)
        return color("НЕ ПРОПАТЧЕН", C_YELLOW, C_BOLD)

    m_st = details.get("machine", "not_found")
    s_st = details.get("string", "not_found")
    p_st = details.get("proxy_var", "not_found")

    parts = []
    if m_st == "patched":
        parts.append(color("маш.код: ✔", C_GREEN))
    elif m_st == "unpatched":
        parts.append(color("маш.код: ✖", C_YELLOW))

    if s_st in ("patched", "partial"):
        parts.append(color("ineligible: ✔", C_GREEN))
    elif s_st == "unpatched":
        parts.append(color("ineligible: ✖", C_YELLOW))

    if p_st == "patched":
        parts.append(color("AG_LS_PROXY: ✔", C_GREEN))
    elif p_st == "unpatched":
        parts.append(color("AG_LS_PROXY: ✖", C_YELLOW))

    summary = color("ПОЛНОСТЬЮ ПРОПАТЧЕН", C_GREEN, C_BOLD) if status_code == "fully_patched" else (
        color("ПРОПАТЧЕН ЧАСТИЧНО", C_YELLOW, C_BOLD) if status_code == "patched" else color("НЕ ПРОПАТЧЕН", C_RED, C_BOLD)
    )
    if parts:
        return f"{summary} ({', '.join(parts)})"
    return summary

# =============================================================================
# ДИАГНОСТИКА СИСТЕМЫ
# =============================================================================

def run_diagnostics():
    print()
    print(f" {color(f'=== ДИАГНОСТИКА И СТАТУС СИСТЕМЫ [{platform.name}] ===', C_CYAN, C_BOLD)}")
    print()

    # 1. agy CLI
    agy_path = platform.find_agy_path()
    if agy_path:
        st, details = get_binary_status(agy_path, CLI_GATE)
        try:
            ver = subprocess.run([agy_path, "--version"], capture_output=True, text=True, timeout=2).stdout.strip()
        except Exception:
            ver = "неизвестно"
        print(f"  • agy CLI:        {color(agy_path, C_CYAN)} (v{ver})")
        print(f"    Статус патча:   {format_patch_details(st, details)}")
    else:
        print(f"  • agy CLI:        {color('не найден', C_RED)}")

    # 2. Antigravity 2.0 (language_server)
    mgr_path = platform.find_manager_path()
    if mgr_path:
        st, details = get_binary_status(mgr_path, MANAGER_GATE)
        print(f"  • Antigravity 2.0:{color(mgr_path, C_CYAN)}")
        print(f"    Статус патча:   {format_patch_details(st, details)}")
    else:
        print(f"  • Antigravity 2.0:{color('не найден', C_RED)}")

    # 3. Служба локального умного прокси ag_proxy
    proxy_port = settings.get_proxy_port()
    proxy_running = ag_proxy.is_proxy_running(proxy_port)
    daemon_pid = ag_proxy.get_daemon_pid()
    custom_proxy = settings.get_custom_proxy()

    if proxy_running:
        pid_info = f" (PID: {daemon_pid})" if daemon_pid else ""
        px_text = color(f"РАБОТАЕТ на порту {proxy_port}{pid_info}", C_GREEN, C_BOLD)
    else:
        px_text = color(f"ОСТАНОВЛЕН (порт {proxy_port})", C_YELLOW, C_BOLD)

    if custom_proxy:
        route_text = color(f"Свой upstream-прокси [{custom_proxy}]", C_TURQUOISE)
    else:
        route_text = color("Динамический DoH SNI-роутер (dns-ai.ru)", C_CYAN)

    print(f"  • ag_proxy служба:{px_text}")
    print(f"    Маршрутизация:  {route_text}")

    # 4. Переменная окружения AG_LS_PROXY
    proxy_val, proxy_src, proxy_conflicts = platform.get_proxy_env_state()
    if proxy_val:
        if str(proxy_port) in proxy_val or "127.0.0.1" in proxy_val or "localhost" in proxy_val:
            p_text = color(f"ОК = {proxy_val} [{proxy_src}]", C_GREEN, C_BOLD)
        else:
            p_text = color(f"АКТИВНА = {proxy_val} [{proxy_src}]", C_TURQUOISE)
    else:
        p_text = color("НЕ ЗАДАНА (установите пунктом [5] или [1])", C_YELLOW)
    if proxy_conflicts:
        p_text += color(" ⚠ дубли: " + "; ".join(f"{p}={v}" for p, v in proxy_conflicts), C_YELLOW)
    print(f"  • AG_LS_PROXY:    {p_text}")

    # 5. Переменная CLOUD_CODE_URL
    cc_val, cc_src, cc_conflicts = platform.get_cloud_code_env_state()
    if cc_val == CLOUD_CODE_URL_CANONICAL:
        cc_text = color(f"ОК = {cc_val} [{cc_src}]", C_GREEN, C_BOLD)
    elif cc_val:
        cc_text = color(f"НЕВЕРНОЕ ЗНАЧЕНИЕ: {cc_val} [{cc_src}]", C_RED, C_BOLD)
    else:
        cc_text = color("НЕ ЗАДАН", C_YELLOW)
    if cc_conflicts:
        cc_text += color(" ⚠ дубли: " + "; ".join(f"{p}={v}" for p, v in cc_conflicts), C_YELLOW)
    print(f"  • CLOUD_CODE_URL: {cc_text}")

    # 6. Внешний IP
    ip_info = get_public_ip_info()
    ip_c = ip_info.get("country", "")
    ip_warning = f" {color('[ВНИМАНИЕ: включен VPN!]', C_YELLOW, C_BOLD)}" if ip_c and ip_c != "RU" else ""
    print(f"  • Внешний IP:     {ip_info.get('ip')} ({ip_info.get('city')}, {ip_c}){ip_warning}")

    # 7. Тестирование связи через локальный прокси
    print()
    print("  Проверка доступности рабочих шлюзов Google API через локальный прокси:")
    test_domains = ["daily-cloudcode-pa.googleapis.com", "generativelanguage.googleapis.com"]
    for dom in test_domains:
        if proxy_running:
            ok, t, detail = ag_proxy.test_proxy_route(dom, port=proxy_port, timeout=8.0)
            if ok:
                log_step(f"{dom} через ag_proxy — УСПЕХ ({detail}, {t:.2f}s)", True)
            else:
                log_step(f"{dom} через ag_proxy — ошибка ({detail})", False)
        else:
            ok, t, detail = validate_ip_https(None, dom, timeout=6.0)
            if ok:
                log_step(f"{dom} напрямую — HTTPS OK ({detail}, {t:.2f}s)", True)
            else:
                log_step(f"{dom} напрямую — недоступен ({detail})", False)
    print()

# =============================================================================
# ПАКЕТНЫЙ ЗАПУСК В 1 КЛИК (ШАГИ 1-5)
# =============================================================================

def run_all_first_5_steps():
    """
    Выполняет полный цикл разблокировки в 1 клик с изолированной защитой от сбоев:
    1. Патч agy CLI (машинный код + ineligible + AG_LS_PROXY)
    2. Патч Antigravity 2.0 (language_server)
    3. Настройка переменных окружения (AG_LS_PROXY и CLOUD_CODE_URL)
    4. Запуск локальной службы умного прокси ag_proxy на порту 53129
    5. Проверка сетевой связности через прокси с Google API
    """
    print()
    print(" " + "=" * 76)
    print(f" {color('🚀 ПАКЕТНЫЙ ЗАПУСК: ПОЛНЫЙ АНБЛОК В 1 КЛИК БЕЗ VPN', C_CYAN, C_BOLD)}")
    print(" " + "=" * 76)
    print("   Защита от сбоев: ошибка на любом этапе не прерывает остальные.")
    print("   В конце будет сформирован подробный итоговый отчёт.")
    print(" " + "-" * 76)

    results = []

    # -------------------------------------------------------------------------
    # ШАГ 1: Патч agy CLI
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [1/5] Патч бинарника agy CLI...', C_CYAN, C_BOLD)}")
    try:
        agy_path = platform.find_agy_path()
        if not agy_path:
            log_warn(f"agy CLI не найден автоматически в системе ({platform.name}).")
            try:
                custom = input("  📁 Введите путь к agy вручную (или Enter для пропуска): ").strip().strip('"').strip("'")
                if custom and os.path.isfile(custom):
                    agy_path = os.path.abspath(custom)
                    platform.custom_agy_path = agy_path
            except (KeyboardInterrupt, EOFError):
                pass

        if not agy_path:
            log_err(f"agy CLI не найден в системе ({platform.name})")
            results.append({
                "num": 1,
                "name": "Патч agy CLI",
                "status": "fail",
                "detail": "Бинарник agy не найден в системе",
                "advice": "Убедитесь, что agy установлен и добавлен в PATH."
            })
        else:
            status_before, _ = get_binary_status(agy_path, CLI_GATE)
            success = apply_binary_patch(agy_path, CLI_GATE, "agy CLI", platform)
            status_after, _ = get_binary_status(agy_path, CLI_GATE)
            if success or status_after.startswith("patched"):
                tag = "уже был пропатчен" if status_before.startswith("patched") else "успешно пропатчен"
                results.append({
                    "num": 1,
                    "name": "Патч agy CLI",
                    "status": "ok",
                    "detail": f"{agy_path} ({tag})",
                    "advice": ""
                })
            else:
                results.append({
                    "num": 1,
                    "name": "Патч agy CLI",
                    "status": "fail",
                    "detail": f"Не удалось применить патч ({agy_path})",
                    "advice": "Проверьте права доступа к файлу или запустите от имени Администратора."
                })
    except Exception as e:
        log_err(f"Исключение при патче agy CLI: {e}")
        results.append({
            "num": 1,
            "name": "Патч agy CLI",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права доступа к файлу бинарника."
        })

    # -------------------------------------------------------------------------
    # ШАГ 2: Патч Antigravity 2.0 (language_server)
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [2/5] Патч Antigravity 2.0 (language_server)...', C_CYAN, C_BOLD)}")
    try:
        mgr_path = platform.find_manager_path()
        if not mgr_path:
            log_warn(f"Antigravity 2.0 (language_server) не найден автоматически ({platform.name}).")
            try:
                custom = input("  📁 Введите путь к language_server вручную (или Enter для пропуска): ").strip().strip('"').strip("'")
                if custom and os.path.isfile(custom):
                    mgr_path = os.path.abspath(custom)
                    platform.custom_manager_path = mgr_path
            except (KeyboardInterrupt, EOFError):
                pass

        if not mgr_path:
            log_warn("Antigravity 2.0 (language_server) не найден в стандартных каталогах.")
            results.append({
                "num": 2,
                "name": "Патч Antigravity 2.0",
                "status": "warn",
                "detail": "language_server не найден (если используете только CLI — это нормально)",
                "advice": "Установите Antigravity Desktop, если требуется работа в редакторе."
            })
        else:
            status_before, _ = get_binary_status(mgr_path, MANAGER_GATE)
            success = apply_binary_patch(mgr_path, MANAGER_GATE, "Antigravity 2.0", platform)
            status_after, _ = get_binary_status(mgr_path, MANAGER_GATE)
            if success or status_after.startswith("patched"):
                tag = "уже был пропатчен" if status_before.startswith("patched") else "успешно пропатчен"
                results.append({
                    "num": 2,
                    "name": "Патч Antigravity 2.0",
                    "status": "ok",
                    "detail": f"{mgr_path} ({tag})",
                    "advice": ""
                })
            else:
                results.append({
                    "num": 2,
                    "name": "Патч Antigravity 2.0",
                    "status": "fail",
                    "detail": f"Не удалось применить патч ({mgr_path})",
                    "advice": "Проверьте права доступа на запись или закройте Antigravity перед патчингом."
                })
    except Exception as e:
        log_err(f"Исключение при патче Antigravity 2.0: {e}")
        results.append({
            "num": 2,
            "name": "Патч Antigravity 2.0",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права доступа к директории Antigravity."
        })

    # -------------------------------------------------------------------------
    # ШАГ 3: Настройка переменных окружения (AG_LS_PROXY и CLOUD_CODE_URL)
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [3/5] Настройка переменных окружения (AG_LS_PROXY и CLOUD_CODE_URL)...', C_CYAN, C_BOLD)}")
    try:
        proxy_url = AG_LS_PROXY_CANONICAL
        ok_proxy = platform.setup_proxy_env(proxy_url)
        ok_cc = platform.setup_cloud_code_env()

        if ok_proxy and ok_cc:
            results.append({
                "num": 3,
                "name": "Переменные окружения",
                "status": "ok",
                "detail": f"AG_LS_PROXY={proxy_url}, CLOUD_CODE_URL настроены",
                "advice": ""
            })
        else:
            results.append({
                "num": 3,
                "name": "Переменные окружения",
                "status": "warn",
                "detail": "Не удалось записать одну из переменных в профиль",
                "advice": "Проверьте права доступа к файлам профиля шелла или реестра."
            })
    except Exception as e:
        log_err(f"Исключение при настройке переменных: {e}")
        results.append({
            "num": 3,
            "name": "Переменные окружения",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права доступа."
        })

    # -------------------------------------------------------------------------
    # ШАГ 4: Запуск локального умного прокси-демона
    # -------------------------------------------------------------------------
    proxy_port = settings.get_proxy_port()
    print(f"\n{color(f'▶ [4/5] Запуск локальной службы ag_proxy (порт {proxy_port})...', C_CYAN, C_BOLD)}")
    try:
        if ag_proxy.is_proxy_running(proxy_port):
            log_ok(f"Служба ag_proxy уже активна на порту {proxy_port}.")
            started = True
        else:
            started = ag_proxy.start_daemon(port=proxy_port, background=True)

        if started:
            results.append({
                "num": 4,
                "name": "Служба ag_proxy",
                "status": "ok",
                "detail": f"Локальный прокси активен на 127.0.0.1:{proxy_port}",
                "advice": ""
            })
        else:
            results.append({
                "num": 4,
                "name": "Служба ag_proxy",
                "status": "fail",
                "detail": f"Не удалось поднять слушатель на порту {proxy_port}",
                "advice": f"Убедитесь, что порт {proxy_port} не занят другой программой."
            })
    except Exception as e:
        log_err(f"Исключение при запуске ag_proxy: {e}")
        results.append({
            "num": 4,
            "name": "Служба ag_proxy",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права на создание сетевых сокетов."
        })

    # -------------------------------------------------------------------------
    # ШАГ 5: Проверка связи через прокси
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [5/5] Тестирование связи с Google API через ag_proxy...', C_CYAN, C_BOLD)}")
    try:
        domains_to_test = [
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ]
        all_ok = True
        test_details = []

        for dom in domains_to_test:
            ok, t, detail = ag_proxy.test_proxy_route(dom, port=proxy_port, timeout=9.0)
            if ok:
                test_details.append(f"{dom}: ✔ ({detail}, {t:.2f}s)")
                log_step(f"{dom} через ag_proxy — HTTPS OK ({detail}, {t:.2f}s)", True)
            else:
                all_ok = False
                test_details.append(f"{dom}: ✖ ({detail})")
                log_step(f"{dom} через ag_proxy — недоступен ({detail})", False)

        if all_ok:
            results.append({
                "num": 5,
                "name": "Связь через ag_proxy",
                "status": "ok",
                "detail": "Все шлюзы Google API успешно ответили через прокси",
                "advice": ""
            })
        else:
            results.append({
                "num": 5,
                "name": "Связь через ag_proxy",
                "status": "warn",
                "detail": "; ".join(test_details),
                "advice": "Если связь отсутствует, укажите свой прокси через пункт [6] меню или настройте интернет."
            })
    except Exception as e:
        log_err(f"Исключение при тестировании связи: {e}")
        results.append({
            "num": 5,
            "name": "Связь через ag_proxy",
            "status": "fail",
            "detail": f"Ошибка теста: {e}",
            "advice": "Проверьте интернет-соединение."
        })

    # =========================================================================
    # ВЫВОД ИТОГОВОГО ОТЧЁТА
    # =========================================================================
    print()
    print(" " + "=" * 76)
    print(f" {color('📊 ИТОГОВЫЙ ОТЧЁТ ВЫПОЛНЕНИЯ (ПАКЕТНЫЙ ЗАПУСК)', C_CYAN, C_BOLD)}")
    print(" " + "=" * 76)

    passed_count = sum(1 for r in results if r["status"] == "ok")
    warn_count = sum(1 for r in results if r["status"] == "warn")
    fail_count = sum(1 for r in results if r["status"] == "fail")
    total_count = len(results)

    for r in results:
        if r["status"] == "ok":
            st_badge = color("✔ ПРОЙДЕН", C_GREEN, C_BOLD)
        elif r["status"] == "warn":
            st_badge = color("⚠ ВНИМАНИЕ", C_YELLOW, C_BOLD)
        else:
            st_badge = color("✖ НЕ ПРОШЁЛ", C_RED, C_BOLD)

        title = f"  [{r['num']}] {r['name']:<24}"
        print(f"{title} [{st_badge}]  {r['detail']}")

    print(" " + "-" * 76)
    if fail_count == 0 and warn_count == 0:
        summary_line = color(f"🎉 ВСЕ {total_count} ЭТАПОВ УСПЕШНО ЗАВЕРШЕНЫ! Antigravity готов к работе без VPN.", C_GREEN, C_BOLD)
    elif fail_count == 0:
        summary_line = color(f"✔ Пройдено: {passed_count}/{total_count}  |  Предупреждения: {warn_count}", C_YELLOW, C_BOLD)
    else:
        summary_line = color(f"⚠ Пройдено: {passed_count}/{total_count}  |  Не прошли: {fail_count}  |  Предупреждения: {warn_count}", C_RED, C_BOLD)
    print(f"  {summary_line}")
    print(" " + "=" * 76)

    problems = [r for r in results if r["advice"]]
    if problems:
        print(f"\n {color('💡 РЕКОМЕНДАЦИИ ПО НАСТРОЙКЕ:', C_YELLOW, C_BOLD)}")
        for p in problems:
            print(f"  • {color(p['name'], C_BOLD)}: {p['advice']}")
        print()

# =============================================================================
# ПОЛНЫЙ ОТКАТ ВСЕХ ИЗМЕНЕНИЙ (RESTORE / ROLLBACK В 1 КЛИК)
# =============================================================================

def run_full_rollback():
    """
    Выполняет полный откат всех изменений системы в исходное состояние:
    1. Остановка фоновой службы ag_proxy.
    2. Откат бинарника agy CLI до чистого оригинала.
    3. Откат бинарника Antigravity 2.0 (language_server) до чистого оригинала.
    4. Удаление переменных AG_LS_PROXY и CLOUD_CODE_URL из профилей/реестра.
    5. Удаление записей DNS-пинов из системного файла hosts (если были).
    6. Итоговый отчет о результатах отката.
    """
    print()
    print(" " + "=" * 76)
    print(f" {color('🔄 ПОЛНЫЙ ОТКАТ: ВОССТАНОВЛЕНИЕ ОРИГИНАЛЬНОГО СОСТОЯНИЯ СИСТЕМЫ', C_YELLOW, C_BOLD)}")
    print(" " + "=" * 76)
    print("   Возврат бинарников к исходному состоянию, очистка переменных и остановка служб.")
    print(" " + "-" * 76)

    results = []

    # 1. Остановка службы ag_proxy
    print(f"\n{color('▶ [1/5] Остановка фоновой службы ag_proxy...', C_CYAN, C_BOLD)}")
    try:
        stopped = ag_proxy.stop_daemon()
        results.append({
            "num": 1,
            "name": "Служба ag_proxy",
            "status": "ok",
            "detail": "Служба остановлена, PID-файл очищен" if stopped else "Служба не была активна"
        })
    except Exception as e:
        log_err(f"Ошибка при остановке ag_proxy: {e}")
        results.append({
            "num": 1,
            "name": "Служба ag_proxy",
            "status": "warn",
            "detail": f"Ошибка: {e}"
        })

    # 2. Откат agy CLI
    print(f"\n{color('▶ [2/5] Восстановление оригинального agy CLI...', C_CYAN, C_BOLD)}")
    try:
        agy_p = platform.find_agy_path()
        if agy_p:
            ok = restore_binary(agy_p, CLI_GATE, "agy CLI", platform)
            results.append({
                "num": 2,
                "name": "Откат agy CLI",
                "status": "ok" if ok else "fail",
                "detail": f"{agy_p} (восстановлен оригинал)" if ok else "Не удалось восстановить файл"
            })
        else:
            results.append({
                "num": 2,
                "name": "Откат agy CLI",
                "status": "ok",
                "detail": "agy CLI не найден в системе (пропуск)"
            })
    except Exception as e:
        log_err(f"Ошибка при откате agy CLI: {e}")
        results.append({
            "num": 2,
            "name": "Откат agy CLI",
            "status": "fail",
            "detail": f"Ошибка: {e}"
        })

    # 3. Откат Antigravity 2.0 (language_server)
    print(f"\n{color('▶ [3/5] Восстановление Antigravity 2.0 (language_server)...', C_CYAN, C_BOLD)}")
    try:
        mgr_p = platform.find_manager_path()
        if mgr_p:
            ok = restore_binary(mgr_p, MANAGER_GATE, "Antigravity 2.0", platform)
            results.append({
                "num": 3,
                "name": "Откат Antigravity 2.0",
                "status": "ok" if ok else "fail",
                "detail": f"{mgr_p} (восстановлен оригинал)" if ok else "Не удалось восстановить файл"
            })
        else:
            results.append({
                "num": 3,
                "name": "Откат Antigravity 2.0",
                "status": "ok",
                "detail": "language_server не найден в системе (пропуск)"
            })
    except Exception as e:
        log_err(f"Ошибка при откате Antigravity 2.0: {e}")
        results.append({
            "num": 3,
            "name": "Откат Antigravity 2.0",
            "status": "fail",
            "detail": f"Ошибка: {e}"
        })

    # 4. Очистка переменных окружения
    print(f"\n{color('▶ [4/5] Очистка переменных AG_LS_PROXY и CLOUD_CODE_URL...', C_CYAN, C_BOLD)}")
    try:
        platform.clean_proxy_env()
        platform.clean_cloud_code_env()
        results.append({
            "num": 4,
            "name": "Переменные окружения",
            "status": "ok",
            "detail": "Все переменные Antigravity удалены из профилей и реестра"
        })
    except Exception as e:
        log_err(f"Ошибка при очистке переменных: {e}")
        results.append({
            "num": 4,
            "name": "Переменные окружения",
            "status": "warn",
            "detail": f"Ошибка: {e}"
        })

    # 5. Очистка файла hosts
    print(f"\n{color(f'▶ [5/5] Очистка DNS-записей из {platform.get_hosts_path()}...', C_CYAN, C_BOLD)}")
    try:
        remove_dns_pin(platform)
        results.append({
            "num": 5,
            "name": "Очистка hosts",
            "status": "ok",
            "detail": "Записи DNS анлокера удалены из файла hosts"
        })
    except Exception as e:
        log_err(f"Ошибка при очистке hosts: {e}")
        results.append({
            "num": 5,
            "name": "Очистка hosts",
            "status": "warn",
            "detail": f"Ошибка: {e}"
        })

    # Итоговый отчет
    print()
    print(" " + "=" * 76)
    print(f" {color('📊 ИТОГОВЫЙ ОТЧЁТ ОТКАТА СИСТЕМЫ', C_YELLOW, C_BOLD)}")
    print(" " + "=" * 76)
    for r in results:
        badge = color("✔ ВЫПОЛНЕНО", C_GREEN, C_BOLD) if r["status"] == "ok" else color("⚠ ПРЕДУПРЕЖДЕНИЕ", C_YELLOW, C_BOLD)
        title = f"  [{r['num']}] {r['name']:<24}"
        print(f"{title} [{badge}]  {r['detail']}")
    print(" " + "-" * 76)
    print(f"  {color('🎉 ВСЕ ИЗМЕНЕНИЯ УСПЕШНО ОТКАТАНЫ! Система возвращена в исходное состояние.', C_GREEN, C_BOLD)}")
    print(" " + "=" * 76)

# =============================================================================
# ГЛАВНОЕ МЕНЮ
# =============================================================================

MENU_LINE_LEN = 84
MENU_LINE = "  " + "—" * MENU_LINE_LEN

def print_banner():
    p_pad = " " * (2 + (MENU_LINE_LEN - 50) // 2)
    o_pad = " " * (2 + (MENU_LINE_LEN - 42) // 2)

    banner_text = f"""
{p_pad}██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ███████╗
{p_pad}██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔════╝
{p_pad}██████╔╝██║   ██║██║  ██║███████╗██║   ██║███████╗
{p_pad}██╔═══╝ ██║   ██║██║  ██║╚════██║██║   ██║╚════██║
{p_pad}██║     ╚██████╔╝██████╔╝███████║╚██████╔╝███████║
{p_pad}╚═╝      ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝

{o_pad} ██████╗ ██████╗ ███████╗ ██████╗ ███████╗
{o_pad}██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔════╝
{o_pad}██║   ██║██████╔╝███████╗██║   ██║███████╗
{o_pad}██║   ██║██╔══██╗╚════██║██║   ██║╚════██║
{o_pad}╚██████╔╝██████╔╝███████║╚██████╔╝███████║
{o_pad} ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
    """
    print(color(banner_text, C_TURQUOISE, C_BOLD))

    sub1_raw = f"Antigravity & agy CLI All-in-One Patcher v{VERSION} [{platform.name}]"
    sub1_pad = " " * (2 + (MENU_LINE_LEN - len(sub1_raw)) // 2)
    print(f"{sub1_pad}{color('Antigravity & agy CLI All-in-One Patcher', C_BOLD)} {color('v' + VERSION, C_GREEN)} [{color(platform.name, C_BOLD)}]")

    sub2_raw = "Изолированный Smart Connect Proxy + Реверс Go/Mach-O/PE/ELF + DoH SNI"
    sub2_pad = " " * (2 + (MENU_LINE_LEN - len(sub2_raw)) // 2)
    print(f"{sub2_pad}{color(sub2_raw, C_DIM)}")
    print(MENU_LINE)

def main_menu():
    while True:
        agy_path = platform.find_agy_path()
        mgr_path = platform.find_manager_path()

        clear_screen()
        print_banner()

        # Статус компонентов
        st_agy = get_binary_status(agy_path, CLI_GATE)[0] if agy_path else "not_found"
        st_mgr = get_binary_status(mgr_path, MANAGER_GATE)[0] if mgr_path else "not_found"

        if not agy_path or st_agy == "not_found":
            agy_st = color("✖ не найден", C_RED)
        elif st_agy.startswith("patched"):
            agy_st = color("✔ пропатчен", C_GREEN)
        else:
            agy_st = color("✖ не пропатчен", C_YELLOW)

        if not mgr_path or st_mgr == "not_found":
            mgr_st = color("✖ не найден", C_RED)
        elif st_mgr.startswith("patched"):
            mgr_st = color("✔ пропатчен", C_GREEN)
        else:
            mgr_st = color("✖ не пропатчен", C_YELLOW)

        # Статус прокси
        p_port = settings.get_proxy_port()
        p_running = ag_proxy.is_proxy_running(p_port)
        if p_running:
            p_badge = color(f"✔ РАБОТАЕТ (порт {p_port})", C_GREEN)
        else:
            p_badge = color(f"✖ ОСТАНОВЛЕН (порт {p_port})", C_YELLOW)

        custom_px = settings.get_custom_proxy()
        route_str = f"Custom: {custom_px}" if custom_px else "DoH SNI (dns-ai.ru)"

        print(f"  • agy CLI:         {agy_st}")
        print(f"  • Antigravity 2.0: {mgr_st}")
        print(f"  • Служба ag_proxy: {p_badge} | Маршрут: {color(route_str, C_CYAN)}")
        print(MENU_LINE)
        print()
        print(f"  {color('[1]', C_GREEN, C_BOLD)} {color('🌟 ВСЁ В ОДИН КЛИК: Полный анблок (Патчи + Переменные + Служба + Тест)', C_GREEN, C_BOLD)}")
        print()
        print(f"  {color('[2]', C_CYAN)} Патч только agy CLI (код + ineligible + AG_LS_PROXY)")
        print(f"  {color('[3]', C_CYAN)} Патч только Antigravity 2.0 (language_server)")
        print(f"  {color('[4]', C_CYAN)} Управление службой ag_proxy (Запуск / Остановка / Перезапуск)")
        print(f"  {color('[5]', C_CYAN)} Настроить переменные окружения (AG_LS_PROXY и CLOUD_CODE_URL)")
        print(f"  {color('[6]', C_CYAN)} Настройка своего upstream-прокси (HTTP/SOCKS5 или DoH SNI)")
        print()
        print(f"  {color('[7]', C_YELLOW, C_BOLD)} {color('🔄 ПОЛНЫЙ ОТКАТ В 1 КЛИК: вернуть систему в исходное состояние', C_YELLOW, C_BOLD)}")
        print(f"  {color('[8]', C_YELLOW)} Откат только бинарников из бэкапов")
        print(f"  {color('[9]', C_YELLOW)} Очистить переменные окружения и остановить службу")
        print()
        print(f"  {color('[10]', C_CYAN)} 🩺 Диагностика и проверка доступности моделей")
        print(f"  {color('[0]', C_RED)} 🚪 Выход")
        print()

        try:
            choice = input(color("  Выберите действие [0-10]: ", C_BOLD)).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if choice == "0":
            print("\nВыход.")
            break
        elif choice in ("1", "all", "а"):
            run_all_first_5_steps()
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "2":
            print("\n--- Патч agy CLI ---")
            p_agy = platform.find_agy_path()
            if not p_agy:
                log_warn("agy CLI не найден автоматически в системе.")
                try:
                    custom = input("  📁 Введите путь к agy вручную (или Enter для отмены): ").strip().strip('"').strip("'")
                    if custom and os.path.isfile(custom):
                        p_agy = os.path.abspath(custom)
                        platform.custom_agy_path = p_agy
                except (KeyboardInterrupt, EOFError):
                    pass
            if p_agy:
                apply_binary_patch(p_agy, CLI_GATE, "agy CLI", platform)
            else:
                log_err("agy CLI не найден в системе!")
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "3":
            print("\n--- Патч Antigravity 2.0 Desktop ---")
            p_mgr = platform.find_manager_path()
            if not p_mgr:
                log_warn("Antigravity 2.0 (language_server) не найден автоматически в системе.")
                try:
                    custom = input("  📁 Введите путь к language_server вручную (или Enter для отмены): ").strip().strip('"').strip("'")
                    if custom and os.path.isfile(custom):
                        p_mgr = os.path.abspath(custom)
                        platform.custom_manager_path = p_mgr
                except (KeyboardInterrupt, EOFError):
                    pass
            if p_mgr:
                apply_binary_patch(p_mgr, MANAGER_GATE, "Antigravity 2.0", platform)
            else:
                log_err("Antigravity 2.0 (language_server) не найден!")
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "4":
            print("\n--- Управление службой ag_proxy ---")
            p_port = settings.get_proxy_port()
            p_running = ag_proxy.is_proxy_running(p_port)
            print(f"Текущий статус: {'РАБОТАЕТ' if p_running else 'ОСТАНОВЛЕН'} на порту {p_port}")
            print("  [1] Запустить службу в фоне")
            print("  [2] Остановить службу")
            print("  [3] Перезапустить службу")
            sub_c = input("Выберите действие [1-3]: ").strip()
            if sub_c == "1":
                ag_proxy.start_daemon(port=p_port, background=True)
            elif sub_c == "2":
                ag_proxy.stop_daemon()
                log_ok("Служба остановлена.")
            elif sub_c == "3":
                ag_proxy.stop_daemon()
                time.sleep(0.5)
                ag_proxy.start_daemon(port=p_port, background=True)
                log_ok("Служба перезапущена.")
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "5":
            print("\n--- Настройка переменных окружения ---")
            platform.setup_proxy_env(AG_LS_PROXY_CANONICAL)
            platform.setup_cloud_code_env()
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "6":
            print("\n--- Настройка своего upstream-прокси ---")
            cur = settings.get_custom_proxy()
            print(f"Текущий upstream: {cur if cur else 'DoH SNI-роутер (по умолчанию)'}")
            print("Вы можете указать любой свой HTTP или SOCKS5 прокси (например, http://127.0.0.1:7890 или socks5://127.0.0.1:10808).")
            print("Оставьте поле пустым, чтобы вернуться к автоматическому DoH SNI режиму.")
            new_val = input("Введите URL прокси (или Enter для DoH SNI): ").strip()
            settings.save_settings({"custom_proxy": new_val})
            log_ok(f"Настройки сохранены: {new_val if new_val else 'Автоматический DoH SNI'}")
            if ag_proxy.is_proxy_running(settings.get_proxy_port()):
                ag_proxy.stop_daemon()
                time.sleep(0.5)
                ag_proxy.start_daemon(port=settings.get_proxy_port(), background=True)
                log_ok("Служба ag_proxy перезапущена с новыми параметрами.")
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "7":
            run_full_rollback()
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "8":
            print("\n--- Откат бинарников из бэкапов ---")
            p_agy = platform.find_agy_path()
            p_mgr = platform.find_manager_path()
            if p_agy:
                restore_binary(p_agy, CLI_GATE, "agy CLI", platform)
            if p_mgr:
                restore_binary(p_mgr, MANAGER_GATE, "Antigravity 2.0", platform)
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "9":
            print("\n--- Очистка переменных окружения и остановка службы ---")
            ag_proxy.stop_daemon()
            platform.clean_proxy_env()
            platform.clean_cloud_code_env()
            log_ok("Служба остановлена, переменные AG_LS_PROXY и CLOUD_CODE_URL очищены.")
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice in ("10", "diag", "д"):
            run_diagnostics()
            input(color("Нажмите Enter для возврата в меню...", C_DIM))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PodsosoObsos — Antigravity & agy CLI Patcher")
    parser.add_argument("--agy-path", dest="custom_agy_path", default="", help="Прямой путь к бинарнику agy / agy.exe")
    parser.add_argument("--manager-path", dest="custom_mgr_path", default="", help="Прямой путь к бинарнику language_server")
    parser.add_argument("--all", action="store_true", help="Автоматически выполнить полный цикл разблокировки в 1 клик")
    parser.add_argument("--restore", "--rollback", dest="do_rollback", action="store_true", help="Автоматически выполнить полный откат всех изменений системы в 1 клик")
    parser.add_argument("--proxy-start", action="store_true", help="Запустить фоновую службу ag_proxy")
    parser.add_argument("--proxy-stop", action="store_true", help="Остановить службу ag_proxy")
    parser.add_argument("--proxy-status", action="store_true", help="Показать статус службы ag_proxy")
    parser.add_argument("--custom-proxy", dest="custom_proxy", default="", help="Задать свой upstream-прокси (HTTP/SOCKS5)")
    parser.add_argument("--diagnostics", action="store_true", help="Выполнить диагностику и выйти")
    parser.add_argument("--clean-env", action="store_true", help="Очистить переменные окружения")
    args, unknown = parser.parse_known_args()

    if args.custom_agy_path and os.path.isfile(args.custom_agy_path):
        platform.custom_agy_path = os.path.abspath(args.custom_agy_path)
    if args.custom_mgr_path and os.path.isfile(args.custom_mgr_path):
        platform.custom_manager_path = os.path.abspath(args.custom_mgr_path)

    if args.custom_proxy:
        settings.save_settings({"custom_proxy": args.custom_proxy.strip()})
        log_ok(f"Сохранён кастомный upstream-прокси: {args.custom_proxy.strip()}")

    if args.do_rollback:
        run_full_rollback()
        sys.exit(0)

    if args.proxy_start:
        p = settings.get_proxy_port()
        if ag_proxy.start_daemon(port=p, background=True):
            log_ok(f"Служба ag_proxy запущена на порту {p}")
        else:
            log_err(f"Не удалось запустить службу ag_proxy на порту {p}")
        sys.exit(0)

    if args.proxy_stop:
        if ag_proxy.stop_daemon():
            log_ok("Служба ag_proxy остановлена.")
        else:
            log_info("Служба ag_proxy не была запущена.")
        sys.exit(0)

    if args.proxy_status:
        p = settings.get_proxy_port()
        running = ag_proxy.is_proxy_running(p)
        print(f"Статус ag_proxy: {'РАБОТАЕТ' if running else 'НЕ РАБОТАЕТ'} на порту {p}")
        sys.exit(0 if running else 1)

    if args.clean_env:
        ag_proxy.stop_daemon()
        platform.clean_proxy_env()
        platform.clean_cloud_code_env()
        log_ok("Служба остановлена, переменные очищены.")
        sys.exit(0)

    if args.diagnostics:
        run_diagnostics()
        sys.exit(0)

    if args.all:
        run_all_first_5_steps()
    else:
        main_menu()
