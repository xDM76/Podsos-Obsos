#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — Common Core Engine (Общие модули и логика)
=============================================================================
  Общие компоненты для всех платформ (macOS / Windows / Linux):
  1. Сигнатуры и машина состояний гейтов Go (Gate, MultiGate).
  2. Ядро бинарного патчинга и отката с сохранением бэкапов.
  3. Сетевой DoH/DNS резолвер и алгоритм поиска SNI-прокси.
  4. Формирование записей hosts и проверка доступности портов.
  5. Базовый абстрактный класс BasePlatform.
=============================================================================
"""

import os
import sys
import re
import shutil
import socket
import json
import urllib.request
import subprocess

VERSION = "1.4.0"

# Константы для изолированного прокси-канала agy / language_server (референс: confeden/Antigravity)
AG_LS_PROXY_DEFAULT_PORT = 53129
AG_LS_PROXY_CANONICAL = f"http://127.0.0.1:{AG_LS_PROXY_DEFAULT_PORT}"

# ANSI Цвета
C_CYAN = "\033[36m"
C_TURQUOISE = "\033[96m\033[38;2;64;224;208m"  # Бирюзовый (Turquoise TrueColor + Bright Cyan fallback)
C_BRIGHT_CYAN = "\033[96m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RESET = "\033[0m"

def color(text, *codes):
    return "".join(codes) + str(text) + C_RESET

def log_ok(msg):
    print(f" {color('✔', C_GREEN, C_BOLD)} {msg}")

def log_warn(msg):
    print(f" {color('⚠', C_YELLOW, C_BOLD)} {msg}")

def log_err(msg):
    print(f" {color('✖', C_RED, C_BOLD)} {msg}")

def log_info(msg):
    print(f" {color('ℹ', C_CYAN, C_BOLD)} {msg}")

def log_step(title, success=True, detail=""):
    mark = color("✔", C_GREEN, C_BOLD) if success else color("✖", C_RED, C_BOLD)
    detail_str = f" ({color(detail, C_DIM)})" if detail else ""
    print(f"   [{mark}] {title}{detail_str}")

def clear_screen():
    """Очистка экрана перед отрисовкой меню.
    ANSI-терминал: стереть экран И скроллбэк, курсор в начало — предыдущие
    экраны не остаются в истории прокрутки. Не-ANSI консоль или пайп:
    прокрутка на высоту терминала пустыми строками (лучшее из возможного)."""
    if os.name == "nt" or sys.platform == "win32":
        os.system("cls")
        return
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        is_tty = False
    term = os.environ.get("TERM", "")
    if is_tty and term and term != "dumb":
        sys.stdout.write("\033[2J\033[3J\033[H")
        sys.stdout.flush()
    else:
        try:
            lines = shutil.get_terminal_size(fallback=(24, 80)).lines
        except Exception:
            lines = 24
        sys.stdout.write("\n" * max(1, lines - 1))
        sys.stdout.flush()

# =============================================================================
# БАЗОВЫЙ КЛАСС ПЛАТФОРМЫ (BasePlatform)
# =============================================================================

class BasePlatform:
    """Интерфейс для платформо-зависимой реализации (macOS / Windows / Linux)."""
    name = "Base"
    custom_agy_path = ""
    custom_manager_path = ""

    def find_agy_path(self) -> str:
        raise NotImplementedError

    def find_manager_path(self) -> str:
        raise NotImplementedError

    def kill_running_processes(self) -> None:
        raise NotImplementedError

    def prepare_writable(self, path: str) -> None:
        raise NotImplementedError

    def post_patch(self, path: str) -> bool:
        return True

    def atomic_replace_file(self, path: str, new_data: bytes) -> None:
        raise NotImplementedError

    def get_hosts_path(self) -> str:
        raise NotImplementedError

    def read_hosts(self) -> str:
        raise NotImplementedError

    def write_hosts(self, new_content: str) -> bool:
        raise NotImplementedError

    def flush_dns_cache(self) -> None:
        raise NotImplementedError

    def setup_cloud_code_env(self) -> bool:
        raise NotImplementedError

    def is_cloud_code_env_set(self) -> bool:
        raise NotImplementedError

    def get_cloud_code_env_state(self):
        """(эффективное значение, источник, [(место, значение), ...] конфликты).
        Конфликт — любое найденное значение CLOUD_CODE_URL, отличное от канонического.
        Переопределяется платформами; дефолт смотрит только на текущую сессию."""
        val = os.environ.get("CLOUD_CODE_URL", "")
        return (val, "текущая сессия" if val else "не найдено", [])

    def setup_proxy_env(self, proxy_url: str = AG_LS_PROXY_CANONICAL) -> bool:
        raise NotImplementedError

    def is_proxy_env_set(self) -> bool:
        raise NotImplementedError

    def get_proxy_env_state(self):
        val = os.environ.get("AG_LS_PROXY", "")
        return (val, "текущая сессия" if val else "не найдено", [])

    def clean_proxy_env(self):
        raise NotImplementedError

    def query_udp_dns(self, domain: str, server_ip: str) -> list:
        raise NotImplementedError

# =============================================================================
# 1. СИГНАТУРЫ И МАШИННЫЙ КОД (Go Binary Gates)
# =============================================================================

class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc="", orig=None):
        self.sig = re.compile(sig, re.S)
        self.patched = re.compile(patched, re.S)
        self.fix = fix
        self.offset = offset
        self.desc = desc
        # Байты оригинала в зоне fix (до-патчные). Заполняются ТОЛЬКО когда
        # они полностью конкретны в сигнатуре — такой гейт обратим байтово-точно.
        self.orig = orig

    def find(self, data):
        patched_offsets = [m.start() + self.offset for m in self.patched.finditer(data)]
        if patched_offsets:
            return ("patched", patched_offsets)
        unpatched_offsets = [m.start() + self.offset for m in self.sig.finditer(data)]
        if not unpatched_offsets:
            raise LookupError("Сигнатура гейта не найдена в бинарнике")
        return ("unpatched", unpatched_offsets)

    def resolve(self, data):
        kind, offsets = self.find(data)
        return kind, offsets, self

    def resolve_all(self, data):
        return [self.resolve(data)]

class MultiGate:
    def __init__(self, *gates, desc=""):
        self.gates = gates
        self.desc = desc

    def resolve_all(self, data):
        matches = []
        err = None
        for g in self.gates:
            try:
                matches.append(g.resolve(data))
            except LookupError as e:
                err = e
        if not matches:
            raise err or LookupError("Ни одна сигнатура MultiGate не совпала")
        return matches

# ----------------- agy CLI Gates -----------------
# Патч НЕ привязан к версиям agy: нигде нет проверки номера версии.
# Matching идёт по байтовым сигнатурам машинного кода; MultiGate перебирает
# весь каталог и применяет всё, что совпало. Если не совпало ничего —
# срабатывает универсальный строковый фолбэк ineligible -> inexigible,
# работающий на любой версии. Названия гейтов — условные метки вариантов
# компиляции (разные регистры/порядок инструкций у Go-компилятора),
# а не фильтры по версиям.
CLI_GATE_X64 = Gate(
    rb"\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85....",
    rb"\x48\x85\xc0\x0f\x84....\x48\x85\xc0\x90\x0f\x85....",
    b"\x48\x85\xc0\x90",
    offset=9,
    desc="eligibility screen off (x64)",
    orig=b"\x80\x78\x08\x00",
)
CLI_GATE_ARM64 = Gate(
    rb"...\xb5...\xb4\x01\x20\x40\x39[\x01\x21\x41\x61\x81\xa1\xc1\xe1].[\x00-\x07]\x37"
    rb"...[\x94-\x97](?:\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9"
    rb"|\xe0\x4f\x00\xf9\xe1\x33\x00\xf9\xe2\x47\x00\xf9\xe3\x2f\x00\xf9)",
    rb"...\xb5...\xb4\x21\x00\x80\x52[\x01\x21\x41\x61\x81\xa1\xc1\xe1].[\x00-\x07]\x37"
    rb"...[\x94-\x97](?:\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9"
    rb"|\xe0\x4f\x00\xf9\xe1\x33\x00\xf9\xe2\x47\x00\xf9\xe3\x2f\x00\xf9)",
    b"\x21\x00\x80\x52",
    offset=8,
    desc="eligibility screen off (arm64 v1)",
    orig=b"\x01\x20\x40\x39",
)
CLI_GATE_ARM64_V2 = Gate(
    rb"\x01\x24\x40\x39...\x36\x01\x20\x40\x39...\x37",
    rb"\x01\x24\x40\x39...\x36\x21\x00\x80\x52...\x37",
    b"\x21\x00\x80\x52",
    offset=8,
    desc="eligibility screen off (arm64 v2)",
    orig=b"\x01\x20\x40\x39",
)
CLI_GATE_ARM64_W4 = Gate(
    rb"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x04\x20\x40\x39"
    rb"[\x04\x24\x44\x64\x84\xa4\xc4\xe4].[\x00-\x07]\x37\x04\x94\x44\xa9",
    rb"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x24\x00\x80\x52"
    rb"[\x04\x24\x44\x64\x84\xa4\xc4\xe4].[\x00-\x07]\x37\x04\x94\x44\xa9",
    b"\x24\x00\x80\x52",
    offset=4,
    desc="eligibility screen off (arm64 w4)",
    orig=b"\x04\x20\x40\x39",
)
CLI_GATE_ARM64_W2 = Gate(
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]",
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]",
    b"\x22\x00\x80\x52",
    offset=8,
    desc="eligibility screen off (arm64 w2)",
    orig=b"\x02\x20\x40\x39",
)

CLI_GATE = MultiGate(
    CLI_GATE_X64,
    CLI_GATE_ARM64,
    CLI_GATE_ARM64_V2,
    CLI_GATE_ARM64_W2,
    CLI_GATE_ARM64_W4,
    desc="agy eligibility screen off",
)

# ----------------- Antigravity 2.0 (language_server) Gates -----------------
MANAGER_GATE_X64 = Gate(
    rb"\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89.\x60",
    rb"\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89.\x60",
    b"\xc6\x40\x08\x01\x90\x90",
    offset=0,
    desc="hasValidAuth=true (x64)",
)
_ARM64_TBZ_W3_BIT0 = rb"[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36"
_ARM64_TOKEN_SETUP = rb"(?:....){1,2}\x03\x10\x06\xa9"
MANAGER_GATE_ARM64 = Gate(
    rb"\x03\x20\x40\x39" + _ARM64_TBZ_W3_BIT0 + _ARM64_TOKEN_SETUP,
    rb"\x23\x00\x80\x52\x03\x20\x00\x39" + _ARM64_TOKEN_SETUP,
    b"\x23\x00\x80\x52\x03\x20\x00\x39",
    offset=0,
    desc="hasValidAuth=true (arm64)",
)

MANAGER_GATE = MultiGate(MANAGER_GATE_X64, MANAGER_GATE_ARM64, desc="language_server auth")

# =============================================================================
# 2. ЯДРО ПАТЧИНГА И ОТКАТА БИНАРНИКОВ
# =============================================================================

BAK_EXT = ".agybak"

def _binary_status_from_data(data, gate_obj):
    """Статус патча по содержимому в памяти (без чтения файла)."""
    states = []
    machine_status = "unknown"
    try:
        for state, _offsets, concrete_g in gate_obj.resolve_all(data):
            states.append((state, concrete_g))
        if all(s[0] == "patched" for s in states):
            machine_status = "patched"
        elif any(s[0] == "unpatched" for s in states):
            machine_status = "unpatched"
    except LookupError:
        machine_status = "not_found"
    except Exception:
        machine_status = "error"

    string_patched = (b"inexigible" in data and b"ineligible" not in data)
    string_unpatched = (b"ineligible" in data)
    string_partial = (b"inexigible" in data and b"ineligible" in data)
    if string_patched:
        string_status = "patched"
    elif string_partial:
        string_status = "partial"
    elif string_unpatched:
        string_status = "unpatched"
    else:
        string_status = "not_found"

    proxy_patched = (b"AG_LS_PROXY" in data and b"https_proxy" not in data)
    proxy_partial = (b"AG_LS_PROXY" in data and b"https_proxy" in data)
    proxy_unpatched = (b"https_proxy" in data)
    if proxy_patched or proxy_partial:
        proxy_status = "patched"
    elif proxy_unpatched:
        proxy_status = "unpatched"
    else:
        proxy_status = "not_found"

    details = {
        "machine": machine_status,
        "machine_states": states,
        "string": string_status,
        "proxy_var": proxy_status
    }

    # Общий статус: fully_patched (все компоненты), patched (частично) или unpatched
    if (machine_status == "patched" or string_status in ("patched", "partial")) and proxy_status == "patched":
        return ("fully_patched", details)
    if machine_status == "patched" or string_status in ("patched", "partial") or proxy_status == "patched":
        return ("patched", details)
    if machine_status == "unpatched" or string_status == "unpatched" or proxy_status == "unpatched":
        return ("unpatched", details)
    return ("unknown", details)

def is_binary_patched(status_code: str) -> bool:
    """Проверяет, применён ли патч к бинарнику (полностью или частично)."""
    if not status_code or not isinstance(status_code, str):
        return False
    return status_code in ("fully_patched", "patched", "patched_string", "patched_fully") or (
        status_code.startswith("patched") and not status_code.startswith("unpatched")
    )

def get_binary_status(path, gate_obj):
    if not path or not os.path.isfile(path):
        return ("not_found", None)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return ("error", None)
    return _binary_status_from_data(data, gate_obj)

def _iter_gates(gate_obj):
    if isinstance(gate_obj, MultiGate):
        return list(gate_obj.gates)
    return [gate_obj]

def revert_patches_inplace(data, gate_obj):
    """Откат патчей прямо в данных (версия бинарника гарантированно сохраняется):
    1) строковый патч прокси: AG_LS_PROXY -> https_proxy;
    2) строковый патч регионов: inexigible -> ineligible;
    3) машинные гейты с известным orig: fix-байты -> оригинальные (байтово-точно)."""
    out = bytearray(data)
    reverted = 0
    notes = []

    # 1. Снятие патча переменной прокси (AG_LS_PROXY -> https_proxy)
    proxy_cnt = out.count(b"AG_LS_PROXY")
    if proxy_cnt:
        out = bytearray(bytes(out).replace(b"AG_LS_PROXY", b"https_proxy"))
        reverted += proxy_cnt
        notes.append(f"строковый патч прокси снят: AG_LS_PROXY -> https_proxy ({proxy_cnt} вхожд.)")

    # 2. Снятие строкового патча региона
    in_tiers = out.count(b"inexigible_tiers")
    if in_tiers:
        out = bytearray(bytes(out).replace(b"inexigible_tiers", b"ineligible_tiers"))
        reverted += in_tiers
        notes.append(f"строковый патч снят: inexigible_tiers -> ineligible_tiers ({in_tiers} вхожд.)")

    in_cnt = out.count(b"inexigible")
    if in_cnt:
        out = bytearray(bytes(out).replace(b"inexigible", b"ineligible"))
        reverted += in_cnt
        notes.append(f"строковый патч снят: inexigible -> ineligible ({in_cnt} вхожд.)")

    # 3. Машинные гейты
    for g in _iter_gates(gate_obj):
        if not g.orig:
            if g.patched.search(bytes(out)):
                notes.append(f"гейт «{g.desc}»: точные байты оригинала неизвестны — оставлен пропатченным")
            continue
        for m in g.patched.finditer(bytes(out)):
            off = m.start() + g.offset
            out[off:off + len(g.orig)] = g.orig
            reverted += 1
            notes.append(f"гейт «{g.desc}» @ 0x{off:x} восстановлен (fix -> оригинал)")
    return bytes(out), reverted, notes

def apply_binary_patch(path, gate_obj, name="Binary", platform=None):
    if not path or not os.path.isfile(path):
        log_err(f"Файл {name} не найден: {path}")
        return False

    if platform:
        platform.kill_running_processes()
        platform.prepare_writable(path)

    # 1. Читаем файл
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        log_err(f"Не удалось прочитать {path}: {e}")
        return False

    # 2. Бэкап ДО-патчной версии (обязателен перед любой записью).
    # Маркер «та же версия»: revert_patches_inplace(текущего) == бэкапу —
    # откат патчей восстанавливает в точности оригинал этого билда
    # (для CLI-гейтов байтово-точно). Размер как маркер НЕ годится:
    # на macOS codesign меняет размер подписи, а соседние билды бывают
    # почти равны по размеру.
    bak = path + BAK_EXT
    current = bytes(data)
    cur_state, _ = _binary_status_from_data(current, gate_obj)
    bak_data = None
    if os.path.exists(bak):
        try:
            with open(bak, "rb") as f:
                bak_data = f.read()
        except Exception:
            bak_data = None

    def _write_bak(payload: bytes, reason: str) -> None:
        try:
            with open(bak, "wb") as f:
                f.write(payload)
            log_ok(f"Бэкап: {reason} ({os.path.basename(bak)})")
        except Exception as e:
            log_warn(f"Не удалось обновить бэкап {bak}: {e}")

    if bak_data is None:
        if is_binary_patched(cur_state):
            _write_bak(current, "ВНИМАНИЕ: бэкапа не было, файл уже пропатчен — сохранён текущий (пропатченный); для валидного оригинала переустановите приложение")
        else:
            _write_bak(current, "сохранена до-патчная версия")
    elif bak_data == current:
        pass  # бэкап уже соответствует текущему файлу
    elif cur_state in ("unpatched", "unpatched_string"):
        # не совпадает с бэкапом: новая версия ИЛИ другая подпись того же файла
        _write_bak(current, "приведён к текущему до-патчному файлу")
    else:
        # Текущий пропатчен: проверяем, хранит ли бэкап оригинал ЭТОГО билда.
        derived, _rev, _notes = revert_patches_inplace(current, gate_obj)
        if bak_data == derived:
            pass  # бэкап — точный оригинал текущей версии
        elif _rev > 0:
            _write_bak(derived, "заменён на оригинал текущей версии (восстановлен откатом патча; прежний не соответствовал этому билду)")
        else:
            # Патч не обратим (гейты без точных orig-байтов) и строк нет.
            # Валидный непропатченный бэкап того же размера трогать НЕЛЬЗЯ —
            # это единственный оригинал этой версии (регрессия: раньше
            # перезаписывался пропатченным файлом и оригинал терялся).
            bak_state, _ = _binary_status_from_data(bak_data, gate_obj)
            if bak_state in ("unpatched", "unpatched_string") and len(bak_data) == len(current):
                log_ok("Бэкап: хранит непропатченный оригинал этой же версии — сохранён.")
            else:
                _write_bak(current, "ВНИМАНИЕ: точный оригинал недоступен — сохранён текущий (пропатченный) файл во избежание даунгрейда при откате")

    # 3. Применение патчей (Машинный гейт + Строковый гейт + Прокси-переменная)
    applied = 0
    already = 0

    # 3.1. Машинные сигнатуры гейта (Go machine code)
    try:
        matches = gate_obj.resolve_all(bytes(data))
        for kind, offsets, g in matches:
            for off in offsets:
                if kind == "patched":
                    already += 1
                    log_step(f"Машинный гейт уже пропатчен: {g.desc} @ 0x{off:x}", True, "изменений не требуется")
                    continue
                data[off:off + len(g.fix)] = g.fix
                applied += 1
                log_step(f"Машинный гейт: {g.desc} @ 0x{off:x}", True)
    except LookupError:
        pass

    # 3.2. Строковый гейт (ineligible -> inexigible и ineligible_tiers -> inexigible_tiers)
    # Снимает блокировку в Protobuf дескрипторах и Go struct tags (confeden/Antigravity)
    in_cnt = data.count(b"ineligible")
    if in_cnt > 0:
        data = bytearray(bytes(data).replace(b"ineligible", b"inexigible"))
        applied += in_cnt
        log_step(f"Строковый гейт: ineligible -> inexigible ({in_cnt} вхожд.)", True)
    elif b"inexigible" in data:
        already += 1
        log_step("Строковый гейт: ineligible уже пропатчен (inexigible)", True, "изменений не требуется")

    in_tiers_cnt = data.count(b"ineligible_tiers")
    if in_tiers_cnt > 0:
        data = bytearray(bytes(data).replace(b"ineligible_tiers", b"inexigible_tiers"))
        applied += in_tiers_cnt
        log_step(f"Строковый гейт: ineligible_tiers -> inexigible_tiers ({in_tiers_cnt} вхожд.)", True)
    elif b"inexigible_tiers" in data:
        already += 1

    # 3.3. Прокси-канал: переименование https_proxy -> AG_LS_PROXY (confeden/Antigravity)
    # Позволяет направить agy и language_server в локальный прокси без ломки системного HTTPS_PROXY
    proxy_cnt = data.count(b"https_proxy")
    if proxy_cnt > 0:
        data = bytearray(bytes(data).replace(b"https_proxy", b"AG_LS_PROXY"))
        applied += proxy_cnt
        log_step(f"Прокси-канал: https_proxy -> AG_LS_PROXY ({proxy_cnt} вхожд.)", True)
    elif b"AG_LS_PROXY" in data:
        already += 1
        log_step("Прокси-канал: AG_LS_PROXY уже активирован в бинарнике", True, "изменений не требуется")

    if applied == 0:
        if already > 0:
            log_ok(f"{name} уже был полностью пропатчен ранее — перезапись не требуется.")
            return True
        log_warn("Патч уже применён или совпадений не обнаружено.")

    # 4. Запись через платформенный адаптер
    try:
        if platform:
            platform.atomic_replace_file(path, bytes(data))
        else:
            with open(path, "wb") as f:
                f.write(data)
    except Exception as e:
        log_err(f"Ошибка записи {path}: {e}")
        return False

    # 5. Пост-патч (codesign на macOS, no-op на Windows)
    if platform:
        platform.post_patch(path)

    log_ok(f"{name} успешно пропатчен!")
    return True

def restore_binary(path, gate_obj, name="Binary", platform=None):
    if not path or not os.path.isfile(path):
        log_warn(f"Файл {name} не найден: {path}")
        return False

    bak = path + BAK_EXT
    bak_data = None
    if os.path.exists(bak):
        try:
            with open(bak, "rb") as f:
                bak_data = f.read()
        except Exception as e:
            log_warn(f"Не удалось прочитать бэкап {bak}: {e}")

    try:
        with open(path, "rb") as f:
            cur = f.read()
    except Exception as e:
        log_err(f"Не удалось прочитать {path}: {e}")
        return False

    st, _ = _binary_status_from_data(cur, gate_obj)
    if st in ("unpatched", "unpatched_string"):
        log_info(f"{name} уже в оригинальном (непропатченном) состоянии — откат не требуется.")
        return True

    def _write_restored(payload: bytes, reason: str) -> bool:
        if platform:
            platform.kill_running_processes()
            platform.prepare_writable(path)
        try:
            if platform:
                # Переподпись обязательна ЛЮБОГО восстановленного содержимого:
                # откат байтов в __TEXT (и сам факт подмены файла) делает
                # прежнюю встроенную подпись недействительной, и macOS
                # убивает бинарник при запуске (killed: 9).
                platform.atomic_replace_file(path, payload)
                platform.post_patch(path)
            else:
                with open(path, "wb") as f:
                    f.write(payload)
        except Exception as e:
            log_err(f"Ошибка восстановления {name}: {e}")
            return False
        log_ok(f"{name}: {reason}")
        return True

    # Байтово-точный оригинал текущего билда (для CLI-гейтов откат точный).
    derived, reverted, notes = revert_patches_inplace(cur, gate_obj)

    # 1) Бэкап непропатчен И в точности равен откаченному текущему => это
    #    оригинал ЭТОЙ версии: восстанавливаем байтово-точно, включая подпись.
    #    (Проверка статуса бэкапа обязательна: бэкап, равный derived, может
    #    сам оказаться пропатченным файлом — тогда это не оригинал.)
    if bak_data is not None and bak_data == derived:
        bak_d_state, _ = _binary_status_from_data(bak_data, gate_obj)
        if bak_d_state in ("unpatched", "unpatched_string"):
            return _write_restored(bak_data, f"восстановлен из {os.path.basename(bak)} (бэкап этой же версии; содержимое байтово-точно, подпись перевыпущена).")

    # 2) Бэкап непропатчен и размер в точности равен текущему — с высокой
    #    вероятностью тот же билд (патч размер не меняет; переустановки
    #    подписи на macOS размер меняют, и тогда сработает ветка 3).
    if bak_data is not None and len(bak_data) == len(cur):
        bak_state, _ = _binary_status_from_data(bak_data, gate_obj)
        if bak_state in ("unpatched", "unpatched_string"):
            return _write_restored(bak_data, f"восстановлен из {os.path.basename(bak)} (бэкап этой же версии).")
        log_warn(f"Бэкап {os.path.basename(bak)} пропатчен — как оригинал не используется.")

    # 3) Откат патча на месте: версия гарантированно сохраняется.
    #    Бэкап от другой версии копировать НЕЛЬЗЯ — это даунгрейдит бинарник.
    if bak_data is not None:
        log_warn(f"Бэкап {os.path.basename(bak)} от ДРУГОЙ версии — копирование даунгрейдило бы бинарник, бэкап НЕ используется.")
    if reverted == 0:
        log_err(f"{name}: патч присутствует, но ни один известный метод отката не применим.")
        return False
    for n in notes:
        log_info(f"  откат: {n}")
    partial = any("неизвестны" in n for n in notes)
    reason = f"патч снят на месте, версия сохранена ({reverted} правок откачено)"
    if partial:
        reason += "; частично: для полного отката переустановите приложение"
    return _write_restored(derived, reason)

# =============================================================================
# 3. СЕТЕВОЙ МОДУЛЬ (DoH HTTP/2, SNI-прокси, Hosts)
# =============================================================================

HOSTS_MARKER_BEGIN = "# PODSOSO_OBSOS_HOSTS_BEGIN"
HOSTS_MARKER_END = "# PODSOSO_OBSOS_HOSTS_END"

# Единственное поддерживаемое значение CLOUD_CODE_URL для agy CLI.
# Старые версии анлокера прописывали cloudcode-pa.googleapis.com — на нём
# CLI зависает; диагностика и пункт [5] теперь приводят переменную сюда.
CLOUD_CODE_URL_CANONICAL = "https://daily-cloudcode-pa.googleapis.com"

DOMAINS_TO_PIN = [
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
]

UDP_PROVIDERS = [
    ("geohide.ru", "45.155.204.190"),
    ("geohide.ru #2", "37.230.192.51"),
    ("comss.one", "83.220.169.155"),
    ("comss.one #2", "212.109.195.93"),
    ("comss.one #3", "195.133.25.16"),
]

REFERENCE_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

def query_doh_dns_ai(domain):
    """Выполняет запрос через DoH HTTP/2 dns.dns-ai.ru с разбором DNS wire format."""
    wire = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for part in domain.split('.'):
        wire += bytes([len(part)]) + part.encode()
    wire += b'\x00\x00\x01\x00\x01'
    ips = []
    
    curl_bin = shutil.which("curl") or "curl"
    try:
        p = subprocess.run([
            curl_bin, '-s', '--http2', '--max-time', '3',
            '-H', 'Content-Type: application/dns-message',
            '--data-binary', '@-',
            'https://dns.dns-ai.ru/dns-query'
        ], input=wire, capture_output=True, timeout=4)
        data = p.stdout
        if len(data) > 12:
            offset = 12
            while wire[offset] != 0:
                offset += 1 + wire[offset]
            offset += 5
            while offset < len(data):
                if data[offset] & 0xc0 == 0xc0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += 1 + data[offset]
                    offset += 1
                if offset + 10 > len(data):
                    break
                atype = int.from_bytes(data[offset:offset+2], 'big')
                rdlen = int.from_bytes(data[offset+8:offset+10], 'big')
                offset += 10
                rdata = data[offset:offset+rdlen]
                offset += rdlen
                if atype == 1 and rdlen == 4:
                    ips.append(socket.inet_ntoa(rdata))
    except Exception:
        pass
    return ips

def get_reference_google_subnets(domain, platform=None):
    """Возвращает подсети прямого маршрута Google CDN для исключения прямых IP."""
    subnets = set()
    if platform:
        for ref in REFERENCE_RESOLVERS:
            try:
                ips = platform.query_udp_dns(domain, ref)
                for line in ips:
                    line = line.strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
                        parts = line.split(".")
                        subnets.add(f"{parts[0]}.{parts[1]}")
            except Exception:
                pass
    # Базовые известные подсети Google CDN / GFE. Расширенный список важен,
    # когда UDP/53 до 8.8.8.8 / 1.1.1.1 режется (типично для RU-сетей) и
    # эталонный запрос ничего не возвращает — иначе реальный Google IP,
    # вернувшийся от анблок-DNS, ошибочно считается прокси и запинится.
    subnets.update([
        "172.217", "142.250", "142.251", "216.58", "74.125", "108.177",
        "64.233", "209.85", "173.194", "216.239",
    ])
    return subnets

def test_ip_port_443(ip):
    try:
        s = socket.create_connection((ip, 443), timeout=2.0)
        s.close()
        return True
    except Exception:
        return False

def validate_ip_https(ip, domain, timeout=8.0):
    """Полная проверка кандидата SNI-прокси: TLS-хендшейк с валидным
    сертификатом + реальный HTTPS-ответ от домена через указанный IP.
    TCP-connect недостаточен: прокси может принимать соединения, но ронять
    реальный (особенно потоковый/gRPC) трафик. Любой HTTP-статус от Google
    (включая 404/401 на корне) доказывает, что маршрут до GFE жив.
    ip=None — проверка текущего системного резолвинга (hosts + DNS)."""
    curl_bin = shutil.which("curl") or "curl"
    args = [curl_bin, "-sS", "-o", "/dev/null", "--http2",
            "-m", str(int(max(2, timeout))), "-w", "%{http_code} %{time_total}"]
    if ip:
        args += ["--resolve", f"{domain}:443:{ip}"]
    args.append(f"https://{domain}/")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 4)
        if p.returncode != 0:
            err = (p.stderr or "").strip().splitlines()
            return (False, 0.0, err[-1] if err else "ошибка curl")
        parts = (p.stdout or "").split()
        code = int(parts[0]) if parts and parts[0].isdigit() else 0
        try:
            t = float(parts[1]) if len(parts) > 1 else 0.0
        except ValueError:
            t = 0.0
        if not (100 <= code < 600):
            return (False, t, f"HTTP {code}")
        return (True, t, f"HTTP {code}")
    except Exception as e:
        return (False, 0.0, str(e))

def get_existing_pins(platform):
    """Возвращает {domain: [ip, ...]} из активного блока пина в hosts
    (поддерживаются маркеры и новой, и старой AG_UNLOCKER-версии)."""
    result = {}
    try:
        hosts = platform.read_hosts()
    except Exception:
        return result
    m = re.search(
        r"# (?:PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_BEGIN(.*?)# (?:PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_END",
        hosts, re.S)
    if not m:
        return result
    for line in m.group(1).splitlines():
        mm = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s*$", line)
        if mm and "googleapis" in mm.group(2):
            result.setdefault(mm.group(2), []).append(mm.group(1))
    return result

def get_public_ip_info():
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": f"PodsosoObsos/{VERSION}"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return {
                "ip": data.get("ip", "неизвестно"),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
            }
    except Exception:
        return {"ip": "не удалось определить", "country": "", "city": "", "org": ""}

def setup_dns_pin(platform):
    log_info("Запуск поиска рабочих SNI-прокси для режима «Без VPN»...")
    ip_info = get_public_ip_info()
    country = ip_info.get("country", "")
    ip_addr = ip_info.get("ip", "")
    print(f"   Внешний IP: {color(ip_addr, C_CYAN)} ({ip_info.get('city')}, {color(country, C_BOLD)})")

    if country and country != "RU":
        log_warn(f"ВНИМАНИЕ: Ваш внешний IP геолоцирован как {country} (не Россия)!")
        log_warn("Анблок-DNS отдают подменяющие IP прокси ТОЛЬКО клиентам из России.")
        log_warn("Если у вас сейчас включен VPN — выключите его и запустите этот пункт снова.")

    pin_results = {} # {domain: [(latency, ip, detail), ...]} — только полностью валидированные
    existing_pins = get_existing_pins(platform)
    if existing_pins:
        log_info("Найден существующий пин в hosts — его IP будут перепроверены вместе с новыми кандидатами.")

    for domain in DOMAINS_TO_PIN:
        ref_blocks = get_reference_google_subnets(domain, platform)
        found_ips = set()

        # 0. Уже запиненные IP перепроверяются всегда (без фильтра подсетей)
        for ip in existing_pins.get(domain, []):
            found_ips.add(ip)

        # 1. Запрос через DoH (dns-ai.ru)
        doh_ips = query_doh_dns_ai(domain)
        for ip in doh_ips:
            b16 = ".".join(ip.split(".")[:2])
            if b16 not in ref_blocks:
                found_ips.add(ip)

        # 2. Запрос через UDP провайдеров
        if platform:
            for prov_name, prov_ip in UDP_PROVIDERS:
                u_ips = platform.query_udp_dns(domain, prov_ip)
                for ip in u_ips:
                    b16 = ".".join(ip.split(".")[:2])
                    if b16 not in ref_blocks:
                        found_ips.add(ip)

        # 3. Полная HTTPS-валидация (TCP-connect и живой порт — недостаточно)
        validated = []
        for ip in found_ips:
            ok, t, detail = validate_ip_https(ip, domain)
            if ok:
                validated.append((t, ip, detail))
        validated.sort()
        if validated:
            pin_results[domain] = validated
            tops = ", ".join(f"{ip} ({t:.2f}s, {d})" for t, ip, d in validated[:2])
            log_ok(f"{domain} -> рабочий SNI-прокси: {tops}")
        else:
            log_warn(f"{domain} -> рабочие прокси не найдены (VPN включен или прокси не проходят HTTPS)")

    if not pin_results:
        log_err("Не найдено ни одного РАБОЧЕГО SNI-прокси (порт может быть открыт, но реальный HTTPS не проходит)!")
        if existing_pins:
            # Устаревший пин опаснее отсутствия пина: он отправляет трафик
            # доменов на мёртвые/захлебывающиеся прокси. Снимаем его.
            log_warn("В hosts остался старый пин — снимаю его, чтобы он не ломал сеть...")
            remove_dns_pin(platform)
        else:
            log_warn("Убедитесь, что VPN ВЫКЛЮЧЕН, интернет активен и повторите попытку.")
        return False

    # Формируем блок hosts — до 2 лучших (быстрейших) валидированных IP на домен
    lines = [HOSTS_MARKER_BEGIN]
    for dom in DOMAINS_TO_PIN:
        for _t, ip, _d in pin_results.get(dom, [])[:2]:
            lines.append(f"{ip:<16} {dom}")
    lines.append(HOSTS_MARKER_END)
    block_text = "\n".join(lines) + "\n"

    # Чтение и обновление hosts через платформенный адаптер
    try:
        old_hosts = platform.read_hosts()
        new_hosts = re.sub(
            r"# (PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_BEGIN.*?# (PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_END\n?",
            "", old_hosts, flags=re.S
        )
        new_hosts = new_hosts.rstrip() + "\n\n" + block_text

        if not platform.write_hosts(new_hosts):
            raise PermissionError("Ошибка записи файла hosts")

        platform.flush_dns_cache()
        log_ok(f"Успешно прописаны SNI-прокси в {platform.get_hosts_path()}!")
        return True
    except Exception as e:
        log_err(f"Не удалось записать в {platform.get_hosts_path()}: {e}")
        return False

def remove_dns_pin(platform):
    try:
        old_hosts = platform.read_hosts()
        if HOSTS_MARKER_BEGIN not in old_hosts and "# AG_UNLOCKER_HOSTS_BEGIN" not in old_hosts:
            log_info(f"В {platform.get_hosts_path()} нет записей анлокера.")
            return True

        new_hosts = re.sub(
            r"# (PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_BEGIN.*?# (PODSOSO_OBSOS|AG_UNLOCKER)_HOSTS_END\n?",
            "", old_hosts, flags=re.S
        )

        if not platform.write_hosts(new_hosts):
            raise PermissionError("Ошибка очистки файла hosts")

        platform.flush_dns_cache()
        log_ok(f"DNS-пин полностью удален из {platform.get_hosts_path()}.")
        return True
    except Exception as e:
        log_err(f"Ошибка очистки {platform.get_hosts_path()}: {e}")
        return False
