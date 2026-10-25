#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — All-in-One Antigravity & agy CLI Patcher (Universal)
=============================================================================
  Кроссплатформенный патчер и сетевой анлокер для macOS, Windows и Linux.
  
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

# Включаем поддержку ANSI VT100 цветов в консоли Windows
if sys.platform == "win32" or os.name == "nt":
    os.system("")

# Импорт общего модуля из текущей (верхней) папки
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import common
from common import (
    VERSION,
    CLOUD_CODE_URL_CANONICAL,
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

# Для совместимости со старыми импортами
HOSTS_FILE = platform.get_hosts_path()

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
        st, _ = get_binary_status(agy_path, CLI_GATE)
        st_text = color("ПРОПАТЧЕН", C_GREEN, C_BOLD) if st.startswith("patched") else color("НЕ ПРОПАТЧЕН", C_YELLOW, C_BOLD)
        try:
            ver = subprocess.run([agy_path, "--version"], capture_output=True, text=True, timeout=2).stdout.strip()
        except Exception:
            ver = "неизвестно"
        print(f"  • agy CLI:        {color(agy_path, C_CYAN)} (v{ver})")
        print(f"    Статус патча:   {st_text}")
    else:
        print(f"  • agy CLI:        {color('не найден', C_RED)}")

    # 2. Antigravity 2.0 (language_server)
    mgr_path = platform.find_manager_path()
    if mgr_path:
        st, _ = get_binary_status(mgr_path, MANAGER_GATE)
        st_text = color("ПРОПАТЧЕН", C_GREEN, C_BOLD) if st.startswith("patched") else color("НЕ ПРОПАТЧЕН", C_YELLOW, C_BOLD)
        print(f"  • Antigravity 2.0:{color(mgr_path, C_CYAN)}")
        print(f"    Статус патча:   {st_text}")
    else:
        print(f"  • Antigravity 2.0:{color('не найден', C_RED)}")

    # 3. Hosts DNS Pin
    hosts_active = False
    pinned_count = 0
    old_style_pin = False
    hosts_path = platform.get_hosts_path()
    if os.path.exists(hosts_path):
        try:
            h = platform.read_hosts()
            if common.HOSTS_MARKER_BEGIN in h or "# AG_UNLOCKER_HOSTS_BEGIN" in h:
                hosts_active = True
                old_style_pin = "# AG_UNLOCKER_HOSTS_BEGIN" in h and common.HOSTS_MARKER_BEGIN not in h
                import re
                pinned_count = len(re.findall(r"^\s*([0-9\.]+)\s+.*googleapis\.com", h, re.M))
        except Exception:
            pass

    h_text = color(f"АКТИВЕН ({pinned_count} записей)", C_GREEN, C_BOLD) if hosts_active else color("НЕ НАСТРОЕН", C_YELLOW)
    if old_style_pin:
        h_text += color("  ⚠ пин от СТАРОЙ версии анлокера — обновите пунктом [4] или снимите [7]", C_YELLOW, C_BOLD)
    print(f"  • Режим «Без VPN»:{h_text} ({hosts_path})")
    if hosts_active:
        for ip, dom in get_existing_pins(platform).items():
            print(f"      - {', '.join(ip)} -> {dom}")

    # 4. CLOUD_CODE_URL (эффективное значение + конфликтующие дубли)
    cc_val, cc_src, cc_conflicts = platform.get_cloud_code_env_state()
    if cc_val == CLOUD_CODE_URL_CANONICAL:
        cc_text = color(f"ОК = {cc_val} [{cc_src}]", C_GREEN, C_BOLD)
    elif cc_val:
        cc_text = color(f"НЕВЕРНОЕ ЗНАЧЕНИЕ: {cc_val} [{cc_src}]", C_RED, C_BOLD)
        cc_text += color(f"  → CLI будет зависать; чинит пункт [5] (нужно {CLOUD_CODE_URL_CANONICAL})", C_YELLOW, C_BOLD)
    else:
        cc_text = color("НЕ ЗАДАН", C_YELLOW)
    if cc_conflicts:
        cc_text += color(f"  ⚠ устаревшие дубли: " + "; ".join(f"{p}={v}" for p, v in cc_conflicts), C_YELLOW, C_BOLD)
    print(f"  • CLOUD_CODE_URL: {cc_text}")

    # 5. Внешний IP
    ip_info = get_public_ip_info()
    ip_c = ip_info.get("country", "")
    ip_warning = f" {color('[ВНИМАНИЕ: включен VPN!]', C_YELLOW, C_BOLD)}" if ip_c and ip_c != "RU" else ""
    print(f"  • Внешний IP:     {ip_info.get('ip')} ({ip_info.get('city')}, {ip_c}){ip_warning}")

    # 6. Реальная проверка рабочих доменов (TLS + HTTPS-ответ, не только TCP)
    print()
    print("  Проверка доступности рабочих доменов (полный HTTPS):")
    for dom in ("daily-cloudcode-pa.googleapis.com", "generativelanguage.googleapis.com"):
        ok, t, detail = validate_ip_https(None, dom, timeout=8.0)
        if ok:
            log_step(f"{dom} — HTTPS OK ({detail}, {t:.2f}s)", True)
        else:
            log_step(f"{dom} — недоступен ({detail})", False)
    print()

# =============================================================================
# ПАКЕТНЫЙ ЗАПУСК В 1 КЛИК (ШАГИ 1-5)
# =============================================================================

def run_all_first_5_steps():
    """
    Выполняет все первые 5 пунктов за один запуск с полной изоляцией ошибок.
    Если какой-либо пункт не проходит, выполнение остальных НЕ прерывается.
    В конце формируется структурированный итоговый отчёт: что прошло, что не прошло.
    """
    print()
    print(" " + "=" * 76)
    print(f" {color('🚀 ПАКЕТНЫЙ ЗАПУСК: ВЫПОЛНЕНИЕ ПЕРВЫХ 5 ПУНКТОВ В 1 КЛИК', C_CYAN, C_BOLD)}")
    print(" " + "=" * 76)
    print("   Защита от сбоев: ошибка на любом этапе не прерывает остальные.")
    print("   В конце будет сформирован подробный итоговый отчёт.")
    print(" " + "-" * 76)

    results = []

    # -------------------------------------------------------------------------
    # ШАГ 1: Патч agy CLI (Пункт 2 меню)
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [1/5] Патч бинарника agy CLI...', C_CYAN, C_BOLD)}")
    try:
        agy_path = platform.find_agy_path()
        if not agy_path:
            log_warn(f"agy CLI не найден автоматически в системе ({platform.name}).")
            try:
                custom = input("  📁 Введите путь к agy.exe вручную (или Enter для пропуска): ").strip().strip('"').strip("'")
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
                "advice": "Убедитесь, что agy установлен и добавлен в системный PATH."
            })
        else:
            status_before, _ = get_binary_status(agy_path, CLI_GATE)
            success = apply_binary_patch(agy_path, CLI_GATE, "agy CLI", platform)
            status_after, _ = get_binary_status(agy_path, CLI_GATE)
            if success or status_after in ("patched", "patched_string"):
                tag = "уже был пропатчен" if status_before in ("patched", "patched_string") else "успешно пропатчен"
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
                    "detail": f"Не удалось применить сигнатуры ({agy_path})",
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
    # ШАГ 2: Патч Antigravity 2.0 (language_server) (Пункт 3 меню)
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [2/5] Патч Antigravity 2.0 (language_server)...', C_CYAN, C_BOLD)}")
    try:
        mgr_path = platform.find_manager_path()
        if not mgr_path:
            log_warn(f"Antigravity 2.0 (language_server) не найден автоматически ({platform.name}).")
            try:
                custom = input("  📁 Введите путь к language_server.exe вручную (или Enter для пропуска): ").strip().strip('"').strip("'")
                if custom and os.path.isfile(custom):
                    mgr_path = os.path.abspath(custom)
                    platform.custom_manager_path = mgr_path
            except (KeyboardInterrupt, EOFError):
                pass

        if not mgr_path:
            log_err(f"Antigravity 2.0 (language_server) не найден ({platform.name})")
            results.append({
                "num": 2,
                "name": "Патч Antigravity 2.0",
                "status": "fail",
                "detail": "language_server не найден в стандартных каталогах",
                "advice": "Установите Antigravity 2.0 Desktop в систему."
            })
        else:
            status_before, _ = get_binary_status(mgr_path, MANAGER_GATE)
            success = apply_binary_patch(mgr_path, MANAGER_GATE, "Antigravity 2.0", platform)
            status_after, _ = get_binary_status(mgr_path, MANAGER_GATE)
            if success or status_after in ("patched", "patched_string"):
                tag = "уже был пропатчен" if status_before in ("patched", "patched_string") else "успешно пропатчен"
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
                    "detail": f"Не удалось применить сигнатуры ({mgr_path})",
                    "advice": "Проверьте права доступа на запись или запустите от имени Администратора."
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
    # ШАГ 3: Настройка DNS-пина в hosts (Режим «Без VPN») (Пункт 4 меню)
    # -------------------------------------------------------------------------
    print(f"\n{color(f'▶ [3/5] Настройка DNS-пина в {platform.get_hosts_path()} (Режим «Без VPN»)...', C_CYAN, C_BOLD)}")
    try:
        success = setup_dns_pin(platform)
        if success:
            results.append({
                "num": 3,
                "name": "DNS-пин в файле hosts",
                "status": "ok",
                "detail": "Рабочие SNI-прокси найдены и прописаны в hosts",
                "advice": ""
            })
        else:
            ip_info = get_public_ip_info()
            country = ip_info.get("country", "")
            if country and country != "RU":
                adv = f"Ваш внешний IP: {ip_info.get('ip')} ({country}). Анблок работает ТОЛЬКО с RU IP. Выключите VPN!"
                detail = f"Включен VPN (IP: {ip_info.get('ip')}, регион: {country})"
            else:
                adv = "Убедитесь в наличии интернета и подтвердите запрос UAC / sudo при записи в hosts."
                detail = "Не найдены рабочие SNI-прокси или отменена запись в hosts"
            results.append({
                "num": 3,
                "name": "DNS-пин в файле hosts",
                "status": "warn",
                "detail": detail,
                "advice": adv
            })
    except Exception as e:
        log_err(f"Исключение при настройке DNS-пина: {e}")
        results.append({
            "num": 3,
            "name": "DNS-пин в файле hosts",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права Администратора и работу интернета."
        })

    # -------------------------------------------------------------------------
    # ШАГ 4: Настройка переменной CLOUD_CODE_URL (Пункт 5 меню)
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [4/5] Настройка CLOUD_CODE_URL для agy CLI...', C_CYAN, C_BOLD)}")
    try:
        success = platform.setup_cloud_code_env()
        if success:
            results.append({
                "num": 4,
                "name": "Настройка CLOUD_CODE_URL",
                "status": "ok",
                "detail": "Переменная успешно настроена в профиле системы",
                "advice": ""
            })
        else:
            results.append({
                "num": 4,
                "name": "Настройка CLOUD_CODE_URL",
                "status": "warn",
                "detail": "Не удалось сохранить переменную в профиле",
                "advice": "Проверьте права на запись настроек пользователя."
            })
    except Exception as e:
        log_err(f"Исключение при настройке CLOUD_CODE_URL: {e}")
        results.append({
            "num": 4,
            "name": "Настройка CLOUD_CODE_URL",
            "status": "fail",
            "detail": f"Ошибка: {e}",
            "advice": "Проверьте права доступа к системным переменным."
        })

    # -------------------------------------------------------------------------
    # ШАГ 5: Проверка доступности шлюзов Google API
    # -------------------------------------------------------------------------
    print(f"\n{color('▶ [5/5] Тест связи с серверами Google API...', C_CYAN, C_BOLD)}")
    try:
        domains_to_test = [
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ]
        all_ok = True
        test_details = []
        for dom in domains_to_test:
            ok, t, detail = validate_ip_https(None, dom, timeout=8.0)
            if ok:
                test_details.append(f"{dom}: ✔ ({detail}, {t:.2f}s)")
                log_step(f"{dom} — HTTPS OK ({detail}, {t:.2f}s)", True)
            else:
                all_ok = False
                test_details.append(f"{dom}: ✖ ({detail})")
                log_step(f"{dom} — недоступен ({detail})", False)

        if all_ok:
            results.append({
                "num": 5,
                "name": "Проверка связи с Google API",
                "status": "ok",
                "detail": "Все рабочие домены доступны по порту 443",
                "advice": ""
            })
        else:
            results.append({
                "num": 5,
                "name": "Проверка связи с Google API",
                "status": "warn",
                "detail": "; ".join(test_details),
                "advice": "Если домены недоступны, повторите шаг 3 (DNS-пин) с выключенным VPN."
            })
    except Exception as e:
        log_err(f"Исключение при тестировании связи: {e}")
        results.append({
            "num": 5,
            "name": "Проверка связи с Google API",
            "status": "fail",
            "detail": f"Ошибка теста: {e}",
            "advice": "Проверьте интернет-соединение."
        })

    # =========================================================================
    # ВЫВОД ИТОГОВОГО ОТЧЁТА
    # =========================================================================
    print()
    print(" " + "=" * 76)
    print(f" {color('📊 ИТОГОВЫЙ ОТЧЁТ ВЫПОЛНЕНИЯ (ПЕРВЫЕ 5 ПУНКТОВ)', C_CYAN, C_BOLD)}")
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

        title = f"  [{r['num']}] {r['name']:<28}"
        print(f"{title} [{st_badge}]  {r['detail']}")

    print(" " + "-" * 76)
    if fail_count == 0 and warn_count == 0:
        summary_line = color(f"🎉 ВСЕ {total_count} ПУНКТОВ УСПЕШНО ПРОЙДЕНЫ!", C_GREEN, C_BOLD)
    elif fail_count == 0:
        summary_line = color(f"✔ Пройдено: {passed_count}/{total_count}  |  С предупреждениями: {warn_count}", C_YELLOW, C_BOLD)
    else:
        summary_line = color(f"⚠ Пройдено: {passed_count}/{total_count}  |  Не прошли: {fail_count}  |  Предупреждения: {warn_count}", C_RED, C_BOLD)
    print(f"  {summary_line}")
    print(" " + "=" * 76)

    problems = [r for r in results if r["advice"]]
    if problems:
        print(f"\n {color('💡 РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ ЗАМЕЧАНИЙ:', C_YELLOW, C_BOLD)}")
        for p in problems:
            print(f"  • {color(p['name'], C_BOLD)}: {p['advice']}")
        print()

# =============================================================================
# ГЛАВНОЕ МЕНЮ
# =============================================================================

MENU_LINE_LEN = 84
MENU_LINE = "  " + "—" * MENU_LINE_LEN

def print_banner():
    # Отступы для точного центрирования баннера относительно линии меню (ширина 84)
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

    sub2_raw = "Машинный код arm64/x64 + Сетевой обход БЕЗ VPN (DoH SNI-Proxy)"
    sub2_pad = " " * (2 + (MENU_LINE_LEN - len(sub2_raw)) // 2)
    print(f"{sub2_pad}{color(sub2_raw, C_DIM)}")
    print(MENU_LINE)

def main_menu():
    while True:
        agy_path = platform.find_agy_path()
        mgr_path = platform.find_manager_path()

        # Очистка экрана
        if sys.platform == "win32":
            os.system("cls")
        else:
            print("\033[2J\033[H", end="")

        print_banner()

        # Краткий статус
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

        print(f"  • agy CLI:         {agy_st}")
        print(f"  • Antigravity 2.0: {mgr_st}")
        print(MENU_LINE)
        print()
        print(f"  {color('[1]', C_GREEN, C_BOLD)} {color('🌟 ВСЁ В ОДИН КЛИК: Выполнить все первые 5 пунктов (Безопасный режим + Отчёт)', C_GREEN, C_BOLD)}")
        print()
        print(f"  {color('[2]', C_CYAN)} Патч только agy CLI")
        print(f"  {color('[3]', C_CYAN)} Патч только Antigravity 2.0 (language_server)")
        print(f"  {color('[4]', C_CYAN)} Настроить / Обновить DNS-пин в hosts (Режим «Без VPN»)")
        print(f"  {color('[5]', C_CYAN)} Настроить CLOUD_CODE_URL для agy CLI")
        print()
        print(f"  {color('[6]', C_YELLOW)} 🔄 Откат (RESTORE) бинарников из бэкапов")
        print(f"  {color('[7]', C_YELLOW)} 🧹 Удалить DNS-пин из hosts (Вернуть стандартную сеть)")
        print()
        print(f"  {color('[8]', C_CYAN)} 🩺 Диагностика и статус сети")
        print(f"  {color('[0]', C_RED)} 🚪 Выход")
        print()

        try:
            choice = input(color("  Выберите действие [0-8]: ", C_BOLD)).strip().lower()
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
                    custom = input("  📁 Введите путь к agy / agy.exe вручную (или Enter для отмены): ").strip().strip('"').strip("'")
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
                    custom = input("  📁 Введите путь к language_server / language_server.exe вручную (или Enter для отмены): ").strip().strip('"').strip("'")
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
            print(f"\n--- Настройка DNS-пина в {platform.get_hosts_path()} (Без VPN) ---")
            setup_dns_pin(platform)
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "5":
            print("\n--- Настройка переменной CLOUD_CODE_URL ---")
            platform.setup_cloud_code_env()
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "6":
            print("\n--- Откат бинарников ---")
            p_agy = platform.find_agy_path()
            p_mgr = platform.find_manager_path()
            if p_agy:
                restore_binary(p_agy, "agy CLI", platform)
            if p_mgr:
                restore_binary(p_mgr, "Antigravity 2.0", platform)
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "7":
            print(f"\n--- Очистка {platform.get_hosts_path()} ---")
            remove_dns_pin(platform)
            input(color("\nНажмите Enter для возврата в меню...", C_DIM))
        elif choice == "8":
            run_diagnostics()
            input(color("Нажмите Enter для возврата в меню...", C_DIM))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PodsosoObsos — Antigravity & agy CLI Patcher")
    parser.add_argument("--agy-path", dest="custom_agy_path", default="", help="Прямой путь к бинарнику agy / agy.exe")
    parser.add_argument("--manager-path", dest="custom_mgr_path", default="", help="Прямой путь к бинарнику language_server")
    parser.add_argument("--all", action="store_true", help="Автоматически выполнить первые 5 пунктов в пакетном режиме")
    args, unknown = parser.parse_known_args()

    if args.custom_agy_path and os.path.isfile(args.custom_agy_path):
        platform.custom_agy_path = os.path.abspath(args.custom_agy_path)
    if args.custom_mgr_path and os.path.isfile(args.custom_mgr_path):
        platform.custom_manager_path = os.path.abspath(args.custom_mgr_path)

    if args.all:
        run_all_first_5_steps()
    else:
        main_menu()
