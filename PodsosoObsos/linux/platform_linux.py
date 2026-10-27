#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — Linux Specific Platform Adapter
=============================================================================
  Реализация всех платформенных механизмов для Linux:
  - Поиск путей бинарников agy/antigravity и language_server (PATH, ~/.local/bin, /usr/share, /opt, snap, flatpak)
  - Завершение процессов через pkill
  - Сброс кэша DNS через resolvectl, systemd-resolve, nscd, NetworkManager
  - Запись в /etc/hosts через sudo tee
  - Настройка переменной окружения в ~/.bashrc, ~/.zshrc, ~/.profile
  - Атомарная замена исполняемых файлов (включая fallback через sudo cp)
  - Проверка и сохранение прав исполнения (chmod +x)
=============================================================================
"""

import os
import sys
import re
import shutil
import subprocess
import time
import tempfile
import stat

# Добавляем common в sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
common_dir = os.path.join(parent_dir, "common")
if common_dir not in sys.path:
    sys.path.insert(0, common_dir)

from common import BasePlatform, CLOUD_CODE_URL_CANONICAL, AG_LS_PROXY_CANONICAL, log_ok, log_warn, log_err, log_info

class LinuxPlatform(BasePlatform):
    name = "Linux"
    custom_agy_path = ""
    custom_manager_path = ""

    def find_agy_path(self) -> str:
        if self.custom_agy_path and os.path.isfile(self.custom_agy_path):
            return os.path.abspath(self.custom_agy_path)

        cands = [
            os.path.expanduser("~/.local/bin/agy"),
            os.path.expanduser("~/.local/bin/antigravity"),
            os.path.expanduser("~/.gemini/bin/agy"),
            os.path.expanduser("~/.gemini/bin/antigravity"),
            os.path.expanduser("~/bin/agy"),
            os.path.expanduser("~/bin/antigravity"),
            "/usr/local/bin/agy",
            "/usr/local/bin/antigravity",
            "/usr/bin/agy",
            "/usr/bin/antigravity",
            "/snap/bin/agy",
            "/snap/bin/antigravity",
        ]
        for name in ("agy", "antigravity"):
            w = shutil.which(name)
            if w and w not in cands:
                cands.insert(0, w)

        for c in cands:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return os.path.abspath(c)
        return ""

    def find_manager_path(self) -> str:
        if self.custom_manager_path and os.path.isfile(self.custom_manager_path):
            return os.path.abspath(self.custom_manager_path)

        cands = [
            "/opt/Antigravity/bin/language_server",
            "/opt/antigravity/bin/language_server",
            "/opt/Antigravity/resources/bin/language_server",
            "/opt/Antigravity IDE/resources/app/bin/language_server",
            "/opt/antigravity-ide/resources/app/bin/language_server",
            "/opt/Antigravity IDE/bin/language_server",
            "/opt/antigravity-ide/bin/language_server",
            "/usr/share/antigravity/bin/language_server",
            "/usr/share/antigravity-ide/bin/language_server",
            "/usr/share/antigravity-ide/resources/app/bin/language_server",
            "/usr/lib/antigravity/language_server",
            "/usr/lib/antigravity-ide/bin/language_server",
            os.path.expanduser("~/.local/share/antigravity/bin/language_server"),
            os.path.expanduser("~/.local/share/antigravity-ide/bin/language_server"),
            os.path.expanduser("~/.config/antigravity/bin/language_server"),
            "/var/lib/flatpak/app/com.google.antigravity/current/active/files/bin/language_server",
            os.path.expanduser("~/.local/share/flatpak/app/com.google.antigravity/current/active/files/bin/language_server"),
            "/snap/antigravity/current/bin/language_server",
        ]

        w = shutil.which("language_server")
        if w and w not in cands:
            cands.insert(0, w)

        for c in cands:
            if os.path.isfile(c):
                return os.path.abspath(c)

        # Эвристический поиск по директориям /opt и /usr/share
        search_roots = ["/opt", "/usr/share", os.path.expanduser("~/.local/share")]
        for sroot in search_roots:
            if os.path.isdir(sroot):
                try:
                    for entry in os.listdir(sroot):
                        if "antigravity" in entry.lower():
                            cand = os.path.join(sroot, entry, "bin", "language_server")
                            if os.path.isfile(cand):
                                return os.path.abspath(cand)
                            cand2 = os.path.join(sroot, entry, "resources", "app", "bin", "language_server")
                            if os.path.isfile(cand2):
                                return os.path.abspath(cand2)
                except Exception:
                    pass

        return ""

    def kill_running_processes(self) -> None:
        for name in ("agy", "antigravity", "language_server", "Antigravity", "antigravity-ide"):
            subprocess.run(["pkill", "-f", name], check=False, capture_output=True)
        time.sleep(0.5)

    def prepare_writable(self, path: str) -> None:
        if not os.path.exists(path):
            return
        if not os.access(path, os.W_OK):
            try:
                subprocess.run(["chmod", "u+w", path], check=False, capture_output=True)
            except Exception:
                pass

    def post_patch(self, path: str) -> bool:
        try:
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True
        except Exception:
            return True

    def atomic_replace_file(self, path: str, new_data: bytes) -> None:
        path = os.path.abspath(path)
        if os.path.islink(path):
            path = os.path.realpath(path)

        directory = os.path.dirname(path)
        st = os.stat(path)

        if os.access(directory, os.W_OK):
            fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(new_data)
                    f.flush()
                    os.fsync(f.fileno())
                    try:
                        os.fchown(f.fileno(), st.st_uid, st.st_gid)
                    except OSError:
                        pass
                    try:
                        os.fchmod(f.fileno(), stat.S_IMODE(st.st_mode))
                    except OSError:
                        pass
                os.replace(tmp_path, path)
                tmp_path = None
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        else:
            fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(new_data)
                    f.flush()
                    os.fsync(f.fileno())
                    try:
                        os.fchmod(f.fileno(), stat.S_IMODE(st.st_mode))
                    except OSError:
                        pass
                res = subprocess.run(["sudo", "cp", "-f", tmp_path, path], check=False)
                if res.returncode != 0:
                    raise PermissionError(f"Не удалось записать в {path} через sudo cp")
                subprocess.run(["sudo", "chmod", "a+rx", path], check=False)
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    def get_hosts_path(self) -> str:
        return "/etc/hosts"

    def read_hosts(self) -> str:
        with open(self.get_hosts_path(), "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def write_hosts(self, new_content: str) -> bool:
        hosts_file = self.get_hosts_path()
        try:
            if os.geteuid() == 0:
                with open(hosts_file, "w", encoding="utf-8") as f:
                    f.write(new_content)
                return True
            else:
                p = subprocess.Popen(["sudo", "tee", hosts_file], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
                p.communicate(input=new_content.encode("utf-8"))
                return p.returncode == 0
        except Exception:
            return False

    def flush_dns_cache(self) -> None:
        if shutil.which("resolvectl"):
            subprocess.run(["resolvectl", "flush-caches"], check=False, capture_output=True)
        elif shutil.which("systemd-resolve"):
            subprocess.run(["systemd-resolve", "--flush-caches"], check=False, capture_output=True)

        if shutil.which("systemctl"):
            subprocess.run(["sudo", "systemctl", "try-restart", "nscd"], check=False, capture_output=True)
            subprocess.run(["sudo", "systemctl", "try-restart", "dnsmasq"], check=False, capture_output=True)
            subprocess.run(["sudo", "systemctl", "reload", "NetworkManager"], check=False, capture_output=True)

        log_ok("Кэш DNS Linux очищен.")

    # Порядок приоритета для «эффективного» значения: последний источник
    # выигрывает (интерактивный shell читает свой rc последним).
    ENV_FILES = ("~/.profile", "~/.bashrc", "~/.zshrc")
    _ENV_LINE_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?CLOUD_CODE_URL=.*$", re.M)

    def clean_cloud_code_env(self):
        """Удаляет ВСЕ старые строки CLOUD_CODE_URL из профилей.
        Возвращает (список очищенных файлов, число удалённых строк)."""
        cleaned, removed = [], 0
        for fn in self.ENV_FILES:
            p = os.path.expanduser(fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                n = len(self._ENV_LINE_RE.findall(content))
                if n:
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(self._ENV_LINE_RE.sub("", content))
                    cleaned.append(os.path.basename(p))
                    removed += n
            except Exception:
                pass
        return cleaned, removed

    def setup_cloud_code_env(self) -> bool:
        cleaned, removed = self.clean_cloud_code_env()
        if removed:
            log_ok(f"Удалено старых строк CLOUD_CODE_URL: {removed} ({', '.join(cleaned)})")

        line_to_add = f'export CLOUD_CODE_URL="{CLOUD_CODE_URL_CANONICAL}"'
        # Целевой файл для канонической строки: .zshrc, если есть; иначе .bashrc; иначе .profile
        home = os.path.expanduser("~")
        primary = os.path.join(home, ".zshrc")
        if not os.path.isfile(primary):
            primary = os.path.join(home, ".bashrc")
        if not os.path.isfile(primary):
            primary = os.path.join(home, ".profile")

        try:
            content = ""
            if os.path.exists(primary):
                with open(primary, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            if line_to_add not in content:
                with open(primary, "a", encoding="utf-8") as f:
                    f.write(f"\n# Antigravity CLI without VPN\n{line_to_add}\n")
                log_ok(f"Добавлен CLOUD_CODE_URL={CLOUD_CODE_URL_CANONICAL} в {primary}")
            else:
                log_ok(f"CLOUD_CODE_URL уже прописан корректно в {primary}")
            os.environ["CLOUD_CODE_URL"] = CLOUD_CODE_URL_CANONICAL
            return True
        except Exception as e:
            log_warn(f"Не удалось обновить {primary}: {e}")
            return False

    def is_cloud_code_env_set(self) -> bool:
        effective, _source, _conflicts = self.get_cloud_code_env_state()
        return effective == CLOUD_CODE_URL_CANONICAL

    def get_cloud_code_env_state(self):
        conflicts = []
        effective, source = "", "не найдено"
        for fn in self.ENV_FILES:
            p = os.path.expanduser(fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        s = line.strip()
                        if s.startswith("#") or "CLOUD_CODE_URL=" not in s:
                            continue
                        s = s.replace("export", "", 1).strip()
                        url = s.split("=", 1)[1].strip().strip('"').strip("'")
                        tag = f"~/{os.path.basename(p)}:{i}"
                        # последняя присвоившая строка побеждает (семантика shell)
                        effective, source = url, tag
                        if url != CLOUD_CODE_URL_CANONICAL:
                            conflicts.append((tag, url))
            except Exception:
                pass
        if os.environ.get("CLOUD_CODE_URL"):
            effective, source = os.environ["CLOUD_CODE_URL"], "текущая сессия"
        return effective, source, conflicts

    _PROXY_LINE_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?AG_LS_PROXY=.*$", re.M)

    def clean_proxy_env(self):
        """Удаляет ВСЕ старые строки AG_LS_PROXY из профилей."""
        cleaned, removed = [], 0
        for fn in self.ENV_FILES:
            p = os.path.expanduser(fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                n = len(self._PROXY_LINE_RE.findall(content))
                if n:
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(self._PROXY_LINE_RE.sub("", content))
                    cleaned.append(os.path.basename(p))
                    removed += n
            except Exception:
                pass
        return cleaned, removed

    def setup_proxy_env(self, proxy_url: str = AG_LS_PROXY_CANONICAL) -> bool:
        cleaned, removed = self.clean_proxy_env()
        if removed:
            log_ok(f"Удалено старых строк AG_LS_PROXY: {removed} ({', '.join(cleaned)})")

        line_to_add = f'export AG_LS_PROXY="{proxy_url}"'
        home = os.path.expanduser("~")
        primary = os.path.join(home, ".zshrc")
        if not os.path.isfile(primary):
            primary = os.path.join(home, ".bashrc")
        if not os.path.isfile(primary):
            primary = os.path.join(home, ".profile")

        try:
            content = ""
            if os.path.exists(primary):
                with open(primary, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            if line_to_add not in content:
                with open(primary, "a", encoding="utf-8") as f:
                    f.write(f"\n# Antigravity isolated proxy without VPN\n{line_to_add}\n")
                log_ok(f"Добавлен AG_LS_PROXY={proxy_url} в {primary}")
            else:
                log_ok(f"AG_LS_PROXY уже прописан корректно в {primary}")
            os.environ["AG_LS_PROXY"] = proxy_url
            return True
        except Exception as e:
            log_warn(f"Не удалось обновить {primary}: {e}")
            return False

    def is_proxy_env_set(self) -> bool:
        effective, _source, _conflicts = self.get_proxy_env_state()
        return bool(effective)

    def get_proxy_env_state(self):
        conflicts = []
        effective, source = "", "не найдено"
        for fn in self.ENV_FILES:
            p = os.path.expanduser(fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        s = line.strip()
                        if s.startswith("#") or "AG_LS_PROXY=" not in s:
                            continue
                        s = s.replace("export", "", 1).strip()
                        url = s.split("=", 1)[1].strip().strip('"').strip("'")
                        tag = f"~/{os.path.basename(p)}:{i}"
                        effective, source = url, tag
                        if url != AG_LS_PROXY_CANONICAL:
                            conflicts.append((tag, url))
            except Exception:
                pass
        if os.environ.get("AG_LS_PROXY"):
            effective, source = os.environ["AG_LS_PROXY"], "текущая сессия"
        return effective, source, conflicts

    def query_udp_dns(self, domain: str, server_ip: str) -> list:
        ips = []
        dig_bin = shutil.which("dig")
        if dig_bin:
            try:
                res = subprocess.run([
                    dig_bin, "+short", "+time=2", "+tries=1", domain, f"@{server_ip}"
                ], capture_output=True, text=True, timeout=3)
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
                        ips.append(line)
                if not ips:
                    res = subprocess.run([
                        dig_bin, "+tcp", "+short", "+time=2", "+tries=1", domain, f"@{server_ip}"
                    ], capture_output=True, text=True, timeout=3)
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
                            ips.append(line)
            except Exception:
                pass

        if not ips:
            nslookup_bin = shutil.which("nslookup")
            if nslookup_bin:
                try:
                    res = subprocess.run([
                        nslookup_bin, domain, server_ip
                    ], capture_output=True, text=True, timeout=3)
                    lines = res.stdout.splitlines()
                    after_answer = False
                    for line in lines:
                        if "answer:" in line.lower() or "name:" in line.lower():
                            after_answer = True
                            continue
                        if after_answer and "address:" in line.lower():
                            parts = line.split(":")
                            if len(parts) >= 2:
                                addr = parts[1].strip()
                                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", addr):
                                    ips.append(addr)
                except Exception:
                    pass

        return ips

if __name__ == "__main__":
    main_script = os.path.join(parent_dir, "common", "podsoso_obsos.py")
    if os.path.exists(main_script):
        subprocess.run([sys.executable, main_script] + sys.argv[1:])
