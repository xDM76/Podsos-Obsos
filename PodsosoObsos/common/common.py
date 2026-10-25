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

VERSION = "1.3.0"

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

    def query_udp_dns(self, domain: str, server_ip: str) -> list:
        raise NotImplementedError

# =============================================================================
# 1. СИГНАТУРЫ И МАШИННЫЙ КОД (Go Binary Gates)
# =============================================================================

class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc=""):
        self.sig = re.compile(sig, re.S)
        self.patched = re.compile(patched, re.S)
        self.fix = fix
        self.offset = offset
        self.desc = desc

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
)
CLI_GATE_ARM64_V2 = Gate(
    rb"\x01\x24\x40\x39...\x36\x01\x20\x40\x39...\x37",
    rb"\x01\x24\x40\x39...\x36\x21\x00\x80\x52...\x37",
    b"\x21\x00\x80\x52",
    offset=8,
    desc="eligibility screen off (arm64 v2)",
)
CLI_GATE_ARM64_W4 = Gate(
    rb"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x04\x20\x40\x39"
    rb"[\x04\x24\x44\x64\x84\xa4\xc4\xe4].[\x00-\x07]\x37\x04\x94\x44\xa9",
    rb"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x24\x00\x80\x52"
    rb"[\x04\x24\x44\x64\x84\xa4\xc4\xe4].[\x00-\x07]\x37\x04\x94\x44\xa9",
    b"\x24\x00\x80\x52",
    offset=4,
    desc="eligibility screen off (arm64 w4)",
)
CLI_GATE_ARM64_W2 = Gate(
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]",
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]",
    b"\x22\x00\x80\x52",
    offset=8,
    desc="eligibility screen off (arm64 w2)",
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
    try:
        states = []
        for state, _offsets, concrete_g in gate_obj.resolve_all(data):
            states.append((state, concrete_g))
        if all(s[0] == "patched" for s in states):
            return ("patched", states)
        if any(s[0] == "unpatched" for s in states):
            return ("unpatched", states)
        return ("unknown", None)
    except LookupError:
        # Проверяем строковый патч
        if b"inexigible" in data and b"ineligible" not in data:
            return ("patched_string", None)
        if b"ineligible" in data:
            return ("unpatched_string", None)
        return ("unknown", None)
    except Exception:
        return ("error", None)

def get_binary_status(path, gate_obj):
    if not path or not os.path.isfile(path):
        return ("not_found", None)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return ("error", None)
    return _binary_status_from_data(data, gate_obj)

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

    # 2. Бэкап ДО-патчной версии (обязателен перед любой записью)
    # Если бэкап уже есть, но отличается от текущего файла — бинарник
    # обновился с прошлого патча. Обновляем бэкап только если текущий
    # файл в до-патчном (оригинальном) состоянии, иначе затрём pristine-
    # оригинал уже пропатченным содержимым и откат станет невозможен.
    bak = path + BAK_EXT
    current = bytes(data)
    if os.path.exists(bak):
        try:
            with open(bak, "rb") as f:
                bak_data = f.read()
        except Exception:
            bak_data = None
        if bak_data is not None and bak_data != current:
            cur_state, _ = _binary_status_from_data(current, gate_obj)
            if cur_state in ("unpatched", "unpatched_string"):
                try:
                    with open(bak, "wb") as f:
                        f.write(current)
                    log_ok(f"Обнаружена новая версия бинарника — бэкап обновлён на до-патчную: {os.path.basename(bak)}")
                except Exception as e:
                    log_warn(f"Не удалось обновить бэкап {bak}: {e}")
            elif cur_state in ("patched", "patched_string"):
                log_info(f"Текущий файл уже пропатчен и отличается от бэкапа — бэкап хранит оригинал, не трогаем.")
            else:
                log_warn(f"Содержимое бинарника отличается от бэкапа, состояние не определено — бэкап оставлен как есть.")
    else:
        try:
            with open(bak, "wb") as f:
                f.write(current)
            log_ok(f"Создан бэкап версии до патча: {os.path.basename(bak)}")
        except Exception as e:
            log_warn(f"Не удалось создать бэкап {bak}: {e}")

    # 3. Поиск гейтов
    applied = 0
    try:
        matches = gate_obj.resolve_all(bytes(data))
        for kind, offsets, g in matches:
            for off in offsets:
                data[off:off + len(g.fix)] = g.fix
                applied += 1
                log_step(f"Гейт: {g.desc} @ 0x{off:x}", True)
    except LookupError:
        # Резервный строковый патч
        in_cnt = data.count(b"ineligible")
        if in_cnt > 0:
            data = bytearray(bytes(data).replace(b"ineligible", b"inexigible"))
            applied = in_cnt
            log_step(f"Строковый патч: ineligible -> inexigible ({in_cnt} вхожд.)", True)
        else:
            if b"inexigible" in data:
                log_step("Бинарник уже пропатчен (строка inexigible найдена)", True)
                applied = 1
            else:
                log_err("Не найдена ни машинная сигнатура, ни строка ineligible.")
                return False

    if applied == 0:
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

def restore_binary(path, name="Binary", platform=None):
    bak = path + BAK_EXT
    if not os.path.exists(bak):
        # Если бэкапа нет, но есть строковый патч — инвертируем строку
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = bytearray(f.read())
            out_cnt = data.count(b"inexigible")
            if out_cnt > 0:
                data = bytearray(bytes(data).replace(b"inexigible", b"ineligible"))
                if platform:
                    platform.atomic_replace_file(path, bytes(data))
                    platform.post_patch(path)
                else:
                    with open(path, "wb") as f:
                        f.write(data)
                log_ok(f"Откат выполнен через обратную строковую замену ({out_cnt} вхожд.): {name}")
                return True
        log_warn(f"Бэкап {bak} не найден. Нечего восстанавливать.")
        return False

    if platform:
        platform.kill_running_processes()
        platform.prepare_writable(path)

    try:
        with open(bak, "rb") as f:
            bak_data = f.read()
        try:
            with open(path, "rb") as f:
                if f.read() == bak_data:
                    log_info(f"{name} уже соответствует бэкапу (оригиналу) — откат не требуется.")
                    return True
        except Exception:
            pass
        if platform:
            platform.atomic_replace_file(path, bak_data)
            platform.post_patch(path)
        else:
            with open(path, "wb") as f:
                f.write(bak_data)
        log_ok(f"{name} успешно восстановлен из {os.path.basename(bak)}!")
        return True
    except Exception as e:
        log_err(f"Ошибка восстановления {name}: {e}")
        return False

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
