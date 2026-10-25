#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — macOS Specific Platform Adapter
=============================================================================
  Реализация всех платформенных механизмов для macOS:
  - Ad-hoc codesign переподпись бинарников и .app бандлов
  - Снятие карантина xattr com.apple.quarantine
  - Снятие immutable-флагов chflags nouchg, noschg
  - Поиск путей в /Applications и ~/.local/bin
  - Завершение процессов через pkill
  - Сброс кэша DNS через dscacheutil и mDNSResponder
  - Запись в /etc/hosts через sudo tee
  - Настройка переменной окружения в ~/.zshrc
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

from common import BasePlatform, CLOUD_CODE_URL_CANONICAL, log_ok, log_warn, log_err, log_info

class MacPlatform(BasePlatform):
    name = "macOS"
    custom_agy_path = ""
    custom_manager_path = ""

    def find_agy_path(self) -> str:
        if self.custom_agy_path and os.path.isfile(self.custom_agy_path):
            return os.path.abspath(self.custom_agy_path)
        cands = [
            os.path.expanduser("~/.local/bin/agy"),
            "/usr/local/bin/agy",
            os.path.expanduser("~/bin/agy"),
        ]
        w = shutil.which("agy")
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
            "/Applications/Antigravity.app/Contents/Resources/bin/language_server",
            os.path.expanduser("~/Applications/Antigravity.app/Contents/Resources/bin/language_server"),
            "/Applications/Antigravity.app/Contents/resources/bin/language_server",
        ]
        w = shutil.which("language_server")
        if w and w not in cands:
            cands.append(w)
        for c in cands:
            if os.path.isfile(c):
                return os.path.abspath(c)
        return ""

    def kill_running_processes(self) -> None:
        for name in ("agy", "Antigravity", "language_server", "Antigravity IDE"):
            subprocess.run(["pkill", "-f", name], check=False, capture_output=True)
        time.sleep(0.5)

    def find_app_bundle(self, path: str) -> str:
        p = os.path.abspath(path)
        while p and p != os.path.dirname(p):
            if p.endswith(".app"):
                return p
            p = os.path.dirname(p)
        return ""

    def remove_macos_immutable_flags(self, path: str) -> None:
        if sys.platform != "darwin":
            return
        for args in (
            ["/usr/bin/chflags", "-R", "nouchg,noschg", path],
            ["/usr/bin/chflags", "-R", "nouchg", path],
            ["/usr/bin/chflags", "nouchg", path],
        ):
            try:
                res = subprocess.run(args, check=False, capture_output=True, timeout=20)
                if res.returncode == 0:
                    break
            except Exception:
                pass

    def remove_macos_quarantine(self, path: str) -> None:
        if sys.platform != "darwin":
            return
        try:
            subprocess.run(["/usr/bin/xattr", "-dr", "com.apple.quarantine", path], check=False, capture_output=True, timeout=20)
        except Exception:
            pass

    def prepare_writable(self, path: str) -> None:
        if sys.platform != "darwin":
            return
        try:
            if os.path.exists(path):
                self.remove_macos_immutable_flags(path)
            bundle = self.find_app_bundle(path)
            if bundle:
                self.remove_macos_immutable_flags(bundle)
                self.remove_macos_quarantine(bundle)
        except Exception:
            pass

    def resign_binary(self, path: str) -> bool:
        if sys.platform != "darwin":
            return True
        real = os.path.realpath(path)
        try:
            res = subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", real], check=False, capture_output=True, text=True, timeout=30)
            return res.returncode == 0
        except Exception:
            return False

    def resign_bundle(self, app_path: str) -> bool:
        if sys.platform != "darwin" or not app_path or not os.path.exists(app_path):
            return True
        try:
            self.remove_macos_quarantine(app_path)
            res = subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", app_path], check=False, capture_output=True, text=True, timeout=60)
            return res.returncode == 0
        except Exception:
            return False

    def post_patch(self, path: str) -> bool:
        ok1 = self.resign_binary(path)
        bundle = self.find_app_bundle(path)
        ok2 = True
        if bundle:
            ok2 = self.resign_bundle(bundle)
        return ok1 and ok2

    def atomic_replace_file(self, path: str, new_data: bytes) -> None:
        path = os.path.abspath(path)
        if os.path.islink(path):
            path = os.path.realpath(path)
        self.prepare_writable(path)
        directory = os.path.dirname(path)
        st = os.stat(path)
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
        try:
            subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], check=False)
            subprocess.run(["/usr/bin/killall", "-HUP", "mDNSResponder"], check=False)
            log_ok("Кэш DNS macOS очищен.")
        except Exception:
            pass

    # Порядок приоритета для «эффективного» значения: последний источник
    # выигрывает (zsh читает .zshrc последним и его export перебивает другие).
    ENV_FILES = ("~/.profile", "~/.bashrc", "~/.zprofile", "~/.zshrc")
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

        zshrc = os.path.expanduser("~/.zshrc")
        line_to_add = f'export CLOUD_CODE_URL="{CLOUD_CODE_URL_CANONICAL}"'
        try:
            content = ""
            if os.path.exists(zshrc):
                with open(zshrc, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

            if line_to_add not in content:
                with open(zshrc, "a", encoding="utf-8") as f:
                    f.write(f"\n# Antigravity CLI without VPN\n{line_to_add}\n")
                log_ok(f"Добавлен CLOUD_CODE_URL={CLOUD_CODE_URL_CANONICAL} в ~/.zshrc (для agy CLI без VPN)")
            else:
                log_ok("CLOUD_CODE_URL уже прописан корректно в ~/.zshrc")

            os.environ["CLOUD_CODE_URL"] = CLOUD_CODE_URL_CANONICAL
            return True
        except Exception as e:
            log_warn(f"Не удалось обновить ~/.zshrc: {e}")
            return False

    def is_cloud_code_env_set(self) -> bool:
        effective, _source, _conflicts = self.get_cloud_code_env_state()
        return effective == CLOUD_CODE_URL_CANONICAL

    def get_cloud_code_env_state(self):
        conflicts = []
        effective, source = "", "не найдено"
        # Идём от низкоприоритетных файлов к высокоприоритетным: кто последний — тот и прав
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

    def query_udp_dns(self, domain: str, server_ip: str) -> list:
        ips = []
        dig_bin = shutil.which("dig") or "/usr/bin/dig"
        try:
            res = subprocess.run([
                dig_bin, "+short", "+time=2", "+tries=1", domain, f"@{server_ip}"
            ], capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                line = line.strip()
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
                    ips.append(line)
            if not ips:
                # пробуем TCP
                res = subprocess.run([
                    dig_bin, "+tcp", "+short", "+time=2", "+tries=1", domain, f"@{server_ip}"
                ], capture_output=True, text=True, timeout=3)
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
                        ips.append(line)
        except Exception:
            pass
        return ips

if __name__ == "__main__":
    # Если запущен напрямую из папки mac/
    main_script = os.path.join(parent_dir, "common", "podsoso_obsos.py")
    if os.path.exists(main_script):
        subprocess.run([sys.executable, main_script] + sys.argv[1:])
