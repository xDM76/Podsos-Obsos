#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — Smart Local CONNECT Proxy & SNI Router
=============================================================================
  Умный локальный HTTP CONNECT прокси для полной разблокировки Antigravity
  и agy CLI в России БЕЗ VPN (референс: confeden/Antigravity).

  Ключевые возможности:
  1. Слушает на 127.0.0.1:53129 (и фолбэк-портах 43129, 44129, ...)
  2. Перехватывает вызовы к гейт-хостам Google:
     - cloudcode-pa.googleapis.com
     - daily-cloudcode-pa.googleapis.com
  3. Не трогает сторонний трафик (accounts.google.com, oauth2, telemetry):
     они туннелируются напрямую, вход в аккаунт Google работает штатно.
  4. Адаптивная таблица маршрутов:
     - Маршрут [1]: Свой прокси (Custom upstream: HTTP / SOCKS5, если задан)
     - Маршрут [2]: Динамический DoH SNI-прокси (dns-ai.ru через прямые IP узлов)
     - Маршрут [3]: Напрямую / VPN (если IP не из РФ)
  5. Отслеживание логов клиента (ls_log watchdog):
     - При ошибке 400 "User location is not supported" мгновенно переключает
       маршрут на следующий рабочий SNI-прокси и сбрасывает зависшие сокеты.
     - При успехе (streamGenerateContent ... ResponseID:) фиксирует статус.
  6. Полная изоляция TLS:
     - Сертификаты НЕ подменяются, TLS не дешифруется.
     - Шифрование остаётся сквозным (end-to-end) между клиентом и Google.
=============================================================================
"""

import os
import sys
import time
import socket
import select
import threading
import subprocess
import signal
import re
import urllib.parse
from pathlib import Path

# Импорт модуля настроек
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import settings

DEFAULT_PORT = 53129
FALLBACK_PORTS = [43129, 44129, 45129, 46129, 47129, 48129]

GATE_HOSTS = {
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com"
}

# Надёжные IP-адреса узлов DoH dns.dns-ai.ru (референс из confeden/Antigravity)
DOH_NODES = [
    "194.87.196.13",
    "45.151.102.219",
    "185.251.90.181"
]

# Известные подсети оригинального Google CDN, которые не являются прокси
GOOGLE_CDN_PREFIXES = (
    "172.217.", "142.250.", "142.251.", "216.58.", "74.125.",
    "108.177.", "64.233.", "209.85.", "173.194.", "216.239."
)

RESP_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
RESP_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
RESP_TIMEOUT     = b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"

# =============================================================================
# УПРАВЛЕНИЕ SNI-ПРОКСИ И РЕЗОЛВИНГОМ DoH
# =============================================================================

class RouteManager:
    """Управляет пулом SNI-прокси и штрафами маршрутов при ошибках региона."""
    def __init__(self):
        self.lock = threading.Lock()
        self.cached_ips = {}       # {domain: [ip1, ip2, ...]}
        self.penalties = {}        # {ip: timestamp_until}
        self.last_resolve_time = 0
        self.active_gate_ip = ""
        self.last_confirmed_route = ""

    def penalize(self, ip: str, duration_sec: int = 120):
        with self.lock:
            self.penalties[ip] = time.time() + duration_sec
            if self.active_gate_ip == ip:
                self.active_gate_ip = ""

    def is_penalized(self, ip: str) -> bool:
        with self.lock:
            until = self.penalties.get(ip, 0)
            if time.time() < until:
                return True
            if ip in self.penalties:
                del self.penalties[ip]
            return False

    def resolve_domain_doh(self, domain: str) -> list:
        wire = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in domain.split('.'):
            wire += bytes([len(part)]) + part.encode('ascii')
        wire += b'\x00\x00\x01\x00\x01'

        found_ips = []
        for node in DOH_NODES:
            try:
                p = subprocess.run([
                    'curl', '-s', '--http2', '--max-time', '3',
                    '--resolve', f'dns.dns-ai.ru:443:{node}',
                    '-H', 'Content-Type: application/dns-message',
                    '--data-binary', '@-',
                    'https://dns.dns-ai.ru/dns-query'
                ], input=wire, capture_output=True, timeout=4)
                data = p.stdout
                if len(data) <= 12:
                    continue
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
                        ip_str = socket.inet_ntoa(rdata)
                        if not any(ip_str.startswith(pfx) for pfx in GOOGLE_CDN_PREFIXES):
                            if ip_str not in found_ips:
                                found_ips.append(ip_str)
                if found_ips:
                    break
            except Exception:
                continue
        return found_ips

    def get_candidate_ips(self, domain: str) -> list:
        with self.lock:
            now = time.time()
            if domain not in self.cached_ips or (now - self.last_resolve_time) > 180 or not self.cached_ips[domain]:
                ips = self.resolve_domain_doh(domain)
                if ips:
                    self.cached_ips[domain] = ips
                    self.last_resolve_time = now
            
            # Возвращаем не оштрафованные IP в первую очередь
            all_ips = list(self.cached_ips.get(domain, []))
            unpenalized = [ip for ip in all_ips if not self.is_penalized(ip)]
            if unpenalized:
                return unpenalized
            return all_ips

ROUTES = RouteManager()

# =============================================================================
# ПОДКЛЮЧЕНИЕ К UPSTREAM (CUSTOM PROXY / SNI PROXY / DIRECT)
# =============================================================================

def connect_socks5(socks_host: str, socks_port: int, target_host: str, target_port: int, timeout: float = 5.0) -> socket.socket:
    s = socket.create_connection((socks_host, socks_port), timeout=timeout)
    # Auth negotiation (no auth)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
        s.close()
        raise ConnectionError("SOCKS5: авторизация не поддерживается или отклонена")
    # CONNECT request
    h_bytes = target_host.encode('idna')
    req = b"\x05\x01\x00\x03" + bytes([len(h_bytes)]) + h_bytes + target_port.to_bytes(2, 'big')
    s.sendall(req)
    rep = s.recv(10)
    if len(rep) < 4 or rep[1] != 0:
        s.close()
        raise ConnectionError(f"SOCKS5: ошибка соединения (код {rep[1] if len(rep) > 1 else 'EOF'})")
    return s

def connect_http_proxy(proxy_host: str, proxy_port: int, target_host: str, target_port: int, auth_header: str = "", timeout: float = 5.0) -> socket.socket:
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    if auth_header:
        req += f"Proxy-Authorization: {auth_header}\r\n"
    req += "Proxy-Connection: Keep-Alive\r\n\r\n"
    s.sendall(req.encode('latin1'))
    
    resp_data = b""
    while b"\r\n\r\n" not in resp_data:
        chunk = s.recv(4096)
        if not chunk:
            s.close()
            raise ConnectionError("HTTP Proxy: закрыто соединение до получения статуса")
        resp_data += chunk
    
    status_line = resp_data.split(b"\r\n")[0].decode('latin1', 'replace')
    if " 200 " not in status_line:
        s.close()
        raise ConnectionError(f"HTTP Proxy вернул: {status_line}")
    return s

def connect_custom_upstream(custom_url: str, target_host: str, target_port: int, timeout: float = 5.0) -> socket.socket:
    parsed = urllib.parse.urlparse(custom_url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (1080 if "socks" in scheme else 8080)
    
    auth_header = ""
    if parsed.username or parsed.password:
        import base64
        u = parsed.username or ""
        p = parsed.password or ""
        auth_header = "Basic " + base64.b64encode(f"{u}:{p}".encode('utf-8')).decode('ascii')

    if scheme.startswith("socks"):
        return connect_socks5(host, port, target_host, target_port, timeout=timeout)
    else:
        return connect_http_proxy(host, port, target_host, target_port, auth_header=auth_header, timeout=timeout)

def connect_gate_upstream(target_host: str, target_port: int, custom_proxy: str = "") -> socket.socket:
    # 1. Свой прокси (Custom Upstream), если настроен
    if custom_proxy:
        try:
            sock = connect_custom_upstream(custom_proxy, target_host, target_port, timeout=4.0)
            ROUTES.last_confirmed_route = f"свой прокси ({custom_proxy})"
            return sock
        except Exception as e:
            pass # откат к DoH SNI пулу

    # 2. Пул динамических SNI-прокси
    candidates = ROUTES.get_candidate_ips(target_host)
    last_err = None
    for ip in candidates:
        try:
            s = socket.create_connection((ip, target_port), timeout=3.5)
            ROUTES.active_gate_ip = ip
            ROUTES.last_confirmed_route = f"SNI-прокси ({ip})"
            return s
        except Exception as e:
            last_err = e
            ROUTES.penalize(ip, 60)

    # 3. Фолбэк: напрямую (если VPN включен или прямой доступ разрешён)
    try:
        s = socket.create_connection((target_host, target_port), timeout=4.0)
        ROUTES.last_confirmed_route = "напрямую"
        return s
    except Exception as e:
        raise last_err or e

# =============================================================================
# СЕРВЕР HTTP CONNECT ПРОКСИ
# =============================================================================

class AGProxyServer:
    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port
        self.server_sock = None
        self.running = False
        self.thread = None

    def start(self) -> bool:
        ports_to_try = [self.port] + [p for p in FALLBACK_PORTS if p != self.port]
        bound = False
        for p in ports_to_try:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', p))
                s.listen(100)
                self.server_sock = s
                self.port = p
                bound = True
                break
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        if not bound:
            return False

        self.running = True
        settings.set_proxy_port(self.port)
        
        # Сохраняем активный порт в файл
        port_file = os.path.join(settings.get_config_dir(), "proxy_port")
        try:
            with open(port_file, "w") as f:
                f.write(str(self.port))
        except Exception:
            pass

        self.thread = threading.Thread(target=self._serve_loop, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        port_file = os.path.join(settings.get_config_dir(), "proxy_port")
        if os.path.exists(port_file):
            try:
                os.remove(port_file)
            except Exception:
                pass

    def _serve_loop(self):
        while self.running:
            try:
                client, _ = self.server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except Exception:
                if not self.running:
                    break

    def _handle_client(self, client: socket.socket):
        client.settimeout(10.0)
        try:
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                header_data += chunk
                if len(header_data) > 32768:
                    client.sendall(RESP_BAD_GATEWAY)
                    client.close()
                    return

            first_line = header_data.split(b"\r\n")[0].decode('latin1', 'replace')
            parts = first_line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                client.close()
                return

            target = parts[1]
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                port = int(port_str)
            else:
                host = target
                port = 443

            host_clean = host.strip("[]").strip().lower()
            custom_proxy = settings.get_custom_proxy()

            # Маршрутизация
            if host_clean in GATE_HOSTS:
                upstream = connect_gate_upstream(host_clean, port, custom_proxy=custom_proxy)
            else:
                # Сторонний хост (Google Auth, Telemetry, etc.) — прямой сквозной туннель
                upstream = socket.create_connection((host_clean, port), timeout=6.0)

            client.sendall(RESP_ESTABLISHED)
            self._splice(client, upstream)
        except Exception:
            try:
                client.sendall(RESP_BAD_GATEWAY)
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass

    def _splice(self, s1: socket.socket, s2: socket.socket):
        s1.setblocking(False)
        s2.setblocking(False)
        sockets = [s1, s2]
        try:
            while self.running:
                r, _, x = select.select(sockets, [], sockets, 60.0)
                if x:
                    break
                if not r:
                    break
                for s in r:
                    other = s2 if s is s1 else s1
                    try:
                        data = s.recv(32768)
                        if not data:
                            return
                        other.sendall(data)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except Exception:
                        return
        finally:
            try:
                s1.close()
            except Exception:
                pass
            try:
                s2.close()
            except Exception:
                pass

# =============================================================================
# WATCHDOG ЛОГОВ (LS_LOG TAILER)
# =============================================================================

def find_candidate_logs() -> list:
    logs = []
    # 1. agy CLI логи в ~/.gemini/antigravity-cli/log/
    home = os.path.expanduser("~")
    cli_dir = os.path.join(home, ".gemini", "antigravity-cli", "log")
    if os.path.isdir(cli_dir):
        try:
            files = [os.path.join(cli_dir, f) for f in os.listdir(cli_dir) if f.startswith("cli-") and f.endswith(".log")]
            if files:
                files.sort(key=os.path.getmtime, reverse=True)
                logs.append(files[0])
        except Exception:
            pass

    # 2. Desktop Antigravity логи
    desktop_dirs = []
    if sys.platform == "darwin":
        desktop_dirs.append(os.path.expanduser("~/Library/Application Support/Antigravity/logs"))
    elif sys.platform == "win32" or os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            desktop_dirs.append(os.path.join(appdata, "Antigravity", "logs"))
    else:
        desktop_dirs.append(os.path.expanduser("~/.config/Antigravity/logs"))

    for d in desktop_dirs:
        if os.path.isdir(d):
            ls_log = os.path.join(d, "language_server.log")
            if os.path.isfile(ls_log):
                logs.append(ls_log)
    return logs

def start_log_watchdog(interval: float = 3.0):
    """Фоновый мониторинг логов: обнаружение ошибок 400 и успешных ответов."""
    offsets = {}

    def _watch_loop():
        while True:
            try:
                for log_path in find_candidate_logs():
                    if not os.path.isfile(log_path):
                        continue
                    size = os.path.getsize(log_path)
                    last_offset = offsets.get(log_path)
                    if last_offset is None:
                        # Первое чтение — смотрим последние 64 КБ
                        offsets[log_path] = max(0, size - 65536)
                        continue
                    if size < last_offset:
                        last_offset = 0  # лог ротирован

                    if size > last_offset:
                        with open(log_path, "rb") as f:
                            f.seek(last_offset)
                            new_bytes = f.read(size - last_offset)
                            offsets[log_path] = size
                        
                        lower_text = new_bytes.lower()
                        # Проверка ошибки 400
                        if b"user location is not supported" in lower_text:
                            if ROUTES.active_gate_ip:
                                ROUTES.penalize(ROUTES.active_gate_ip, 180)
                        # Проверка успеха
                        if b"streamgeneratecontent" in lower_text and b"responseid:" in lower_text:
                            if ROUTES.active_gate_ip:
                                settings.save_settings({"last_confirmed_route": f"SNI-прокси {ROUTES.active_gate_ip}"})
            except Exception:
                pass
            time.sleep(interval)

    t = threading.Thread(target=_watch_loop, daemon=True)
    t.start()
    return t

# =============================================================================
# ДЕМОНИЗАЦИЯ И УПРАВЛЕНИЕ ПРОЦЕССОМ
# =============================================================================

def get_pid_file() -> str:
    return os.path.join(settings.get_config_dir(), "ag_proxy.pid")

def get_daemon_pid() -> int:
    pid_path = get_pid_file()
    if os.path.isfile(pid_path):
        try:
            with open(pid_path, "r") as f:
                return int(f.read().strip())
        except Exception:
            pass
    return 0

def test_proxy_route(domain: str, port: int = DEFAULT_PORT, timeout: float = 8.0):
    """
    Проверяет доступность домена через локальный прокси:
    1. Отправляет CONNECT домен:443
    2. Ожидает HTTP/1.1 200 Connection Established
    3. Выполняет TLS handshake с SNI
    Возвращает (ok: bool, latency_sec: float, detail: str).
    """
    import ssl
    start_t = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        req = f"CONNECT {domain}:443 HTTP/1.1\r\nHost: {domain}:443\r\n\r\n".encode("ascii")
        s.sendall(req)
        resp = s.recv(4096)
        if b"200 Connection Established" not in resp:
            s.close()
            return False, 0.0, f"Proxy error: {resp[:50].decode('latin1', errors='replace')}"

        # Делаем TLS Handshake
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(s, server_hostname=domain)
        tls_sock.settimeout(timeout)
        latency = time.time() - start_t
        tls_sock.close()
        return True, latency, "TLS OK via Proxy"
    except Exception as e:
        return False, 0.0, str(e)


def get_log_file() -> str:
    return os.path.join(settings.get_config_dir(), "proxy.log")

def is_proxy_running(port: int = 0) -> bool:
    if port == 0:
        port = settings.get_proxy_port()
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=0.8)
        s.close()
        return True
    except Exception:
        return False

def start_daemon(port: int = DEFAULT_PORT, background: bool = True) -> bool:
    if is_proxy_running(port):
        return True

    if not background:
        # Запуск прямо в текущем процессе
        server = AGProxyServer(port=port)
        if not server.start():
            return False
        start_log_watchdog()
        try:
            while server.running:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            server.stop()
        return True

    # Запуск отвязанного фонового процесса
    script_path = os.path.abspath(__file__)
    log_path = get_log_file()
    pid_path = get_pid_file()

    with open(log_path, "a", encoding="utf-8") as out:
        out.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Запуск ag_proxy демона на порту {port}...\n")
        out.flush()

        if sys.platform == "win32" or os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            proc = subprocess.Popen(
                [sys.executable, script_path, "--foreground", "--port", str(port)],
                stdout=out, stderr=out, stdin=subprocess.DEVNULL,
                creationflags=creationflags
            )
        else:
            proc = subprocess.Popen(
                [sys.executable, script_path, "--foreground", "--port", str(port)],
                stdout=out, stderr=out, stdin=subprocess.DEVNULL,
                start_new_session=True
            )

    try:
        with open(pid_path, "w") as f:
            f.write(str(proc.pid))
    except Exception:
        pass

    # Ждём запуска порта
    for _ in range(15):
        time.sleep(0.2)
        if is_proxy_running(port):
            return True
    return False

def stop_daemon() -> bool:
    pid_path = get_pid_file()
    killed = False
    if os.path.isfile(pid_path):
        try:
            with open(pid_path, "r") as f:
                pid = int(f.read().strip())
            if sys.platform == "win32" or os.name == "nt":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False, capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
            killed = True
        except Exception:
            pass
        try:
            os.remove(pid_path)
        except Exception:
            pass

    # Дополнительно очищаем порт
    port_file = os.path.join(settings.get_config_dir(), "proxy_port")
    if os.path.exists(port_file):
        try:
            os.remove(port_file)
        except Exception:
            pass
    return killed

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PodsosoObsos Smart CONNECT Proxy")
    parser.add_argument("--foreground", action="store_true", help="Запустить в интерактивном/фоновом режиме")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Порт прокси")
    parser.add_argument("--stop", action="store_true", help="Остановить запущенный прокси")
    parser.add_argument("--status", action="store_true", help="Проверить статус")

    args = parser.parse_args()

    if args.stop:
        if stop_daemon():
            print("Прокси успешно остановлен.")
        else:
            print("Прокси не был запущен или PID-файл не найден.")
        sys.exit(0)

    if args.status:
        p = settings.get_proxy_port()
        running = is_proxy_running(p)
        print(f"Статус ag_proxy: {'РАБОТАЕТ' if running else 'НЕ РАБОТАЕТ'} на порту {p}")
        sys.exit(0 if running else 1)

    if args.foreground:
        start_daemon(port=args.port, background=False)
    else:
        if start_daemon(port=args.port, background=True):
            print(f"Прокси успешно запущен в фоновом режиме на порту {args.port}.")
        else:
            print("Не удалось запустить прокси.")
