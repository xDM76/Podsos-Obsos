#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — Windows Specific Platform Adapter
=============================================================================
  Реализация всех платформенных механизмов для Windows:
  - Поиск бинарников agy.exe и language_server.exe (PATH, AppData, Registry, Scoop)
  - Проверка и обработка файловых блокировок (file locking) Windows
  - Завершение процессов через taskkill
  - Безопасная замена исполняемых файлов на Windows
  - UAC повышение прав (RunAs) для записи в hosts и Program Files
  - Сброс DNS кэша через ipconfig /flushdns
  - Персистентная настройка переменной CLOUD_CODE_URL через Registry и setx
  - Резолвинг через nslookup
=============================================================================
"""

import os
import sys
import re
import glob
import shutil
import subprocess
import time
import tempfile

# Добавляем common в sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
common_dir = os.path.join(parent_dir, "common")
if common_dir not in sys.path:
    sys.path.insert(0, common_dir)

from common import BasePlatform, CLOUD_CODE_URL_CANONICAL, log_ok, log_warn, log_err, log_info

class WinPlatform(BasePlatform):
    name = "Windows"
    custom_agy_path = ""
    custom_manager_path = ""

    def is_admin(self) -> bool:
        """Проверяет наличие прав администратора в Windows."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _get_fixed_drives(self) -> list:
        """Возвращает список всех доступных дисков Windows (напр. ['C:', 'D:'])."""
        drives = []
        sys_drv = os.environ.get("SystemDrive", "C:")
        if not sys_drv.endswith(":"):
            sys_drv = sys_drv[:2]
        drives.append(sys_drv)
        import string
        for l in string.ascii_uppercase:
            drv = f"{l}:"
            if drv not in drives and os.path.isdir(drv + "\\"):
                drives.append(drv)
        return drives

    def _get_registry_paths(self) -> list:
        """Читает пути PATH из всех веток реестра Windows (HKLM, HKCU, HKEY_USERS)."""
        paths = []
        try:
            import winreg
            # 1. Системный PATH (HKLM)
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as k:
                    val, _ = winreg.QueryValueEx(k, "Path")
                    if val:
                        paths.extend(val.split(";"))
            except Exception:
                pass

            # 2. Пользовательский PATH (HKCU)
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as k:
                    val, _ = winreg.QueryValueEx(k, "Path")
                    if val:
                        paths.extend(val.split(";"))
            except Exception:
                pass

            # 3. Все профили пользователей (HKEY_USERS\<SID>\Environment)
            # Критично, если скрипт запущен от Administrator, а agy установлен у обычного пользователя
            try:
                with winreg.OpenKey(winreg.HKEY_USERS, "") as u_root:
                    num_subkeys = winreg.QueryInfoKey(u_root)[0]
                    for idx in range(num_subkeys):
                        sid = winreg.EnumKey(u_root, idx)
                        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                            try:
                                with winreg.OpenKey(winreg.HKEY_USERS, rf"{sid}\Environment") as k:
                                    val, _ = winreg.QueryValueEx(k, "Path")
                                    if val:
                                        paths.extend(val.split(";"))
                            except Exception:
                                pass
            except Exception:
                pass
        except Exception:
            pass

        out = []
        for p in paths:
            clean = p.strip().strip('"').rstrip("\\/")
            if clean and os.path.isdir(clean) and clean not in out:
                out.append(clean)
        return out

    def _win_candidate_roots(self) -> list:
        """
        Корневые каталоги для поиска установленных программ на Windows.
        Включает:
        - Переменные окружения текущего процесса
        - Профили ВСЕХ пользователей Windows (C:\\Users\\*, D:\\Users\\*)
        - Каталоги из системного и пользовательского PATH в реестре
        - Корни установленных программ на всех доступных дисках
        """
        roots = []

        # 1. Стандартные переменные окружения
        for var in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramData", "APPDATA"):
            val = os.environ.get(var)
            if val and os.path.isdir(val):
                roots.append(val)
                prog = os.path.join(val, "Programs")
                if os.path.isdir(prog):
                    roots.append(prog)

        user_prof = os.environ.get("USERPROFILE")
        if user_prof:
            for sub in (
                ("scoop", "apps"),
                (".local", "bin"),
                ("AppData", "Local"),
                ("AppData", "Local", "Programs"),
                ("AppData", "Roaming"),
            ):
                cand = os.path.join(user_prof, *sub)
                if os.path.isdir(cand):
                    roots.append(cand)

        scoop = os.environ.get("SCOOP")
        if scoop:
            s_apps = os.path.join(scoop, "apps")
            if os.path.isdir(s_apps):
                roots.append(s_apps)

        # 2. Профили ВСЕХ пользователей Windows (C:\Users\*, D:\Users\*)
        # Это ключевое исправление: когда запуск идет от Administrator, LOCALAPPDATA
        # указывает на C:\Users\Administrator, тогда как agy и Antigravity установлены
        # в профиле пользователя (например C:\Users\<user>\AppData\Local)
        for drv in self._get_fixed_drives():
            users_dir = os.path.join(drv, os.sep, "Users")
            if os.path.isdir(users_dir):
                try:
                    for entry in os.listdir(users_dir):
                        if entry.lower() in ("all users", "default", "default user", "public"):
                            continue
                        u_path = os.path.join(users_dir, entry)
                        if not os.path.isdir(u_path):
                            continue
                        for sub in (
                            ("AppData", "Local"),
                            ("AppData", "Local", "Programs"),
                            ("AppData", "Roaming"),
                            ("scoop", "apps"),
                            (".local", "bin"),
                        ):
                            c_sub = os.path.join(u_path, *sub)
                            if os.path.isdir(c_sub):
                                roots.append(c_sub)
                except Exception:
                    pass

            for d_name in ("Program Files", "Program Files (x86)", "Programs", "agy"):
                d_cand = os.path.join(drv, os.sep, d_name)
                if os.path.isdir(d_cand):
                    roots.append(d_cand)

        # 3. Пути из системного и пользовательского PATH реестра
        roots.extend(self._get_registry_paths())

        # Дедупликация с сохранением порядка
        seen = set()
        deduped = []
        for r in roots:
            norm = os.path.normcase(os.path.abspath(r))
            if norm not in seen:
                seen.add(norm)
                deduped.append(r)
        return deduped

    def find_agy_path(self) -> str:
        """
        Находит путь к бинарнику agy.exe на Windows.
        Ищет:
        0. Пользовательский путь (если задан вручную)
        1. В PATH текущего процесса
        2. В каталогах PATH из системного и пользовательского реестра
        3. Прямым сканированием профилей всех пользователей (C:\\Users\\*\\AppData\\Local\\agy\\bin\\agy.exe)
        4. В scoop, .local, Program Files и корнях дисков
        5. Через запущенный процесс agy
        6. Glob-поиском по candidate_roots
        """
        # 0. Заданный вручную путь
        if self.custom_agy_path and os.path.isfile(self.custom_agy_path):
            return os.path.abspath(self.custom_agy_path)

        # 1. Поиск в PATH текущей сессии
        for binary_name in ("agy.exe", "agy"):
            w = shutil.which(binary_name)
            if w and os.path.isfile(w):
                return os.path.abspath(w)

        # 2. Поиск в каталогах из реестра PATH
        for reg_dir in self._get_registry_paths():
            cand = os.path.join(reg_dir, "agy.exe")
            if os.path.isfile(cand):
                return os.path.abspath(cand)

        # 3. Прямой поиск по профилям ВСЕХ пользователей и дискам Windows
        # (Например C:\Users\<user>\AppData\Local\agy\bin\agy.exe)
        for drv in self._get_fixed_drives():
            patterns = [
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "agy", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Programs", "agy", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Programs", "agy", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "agy", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", "scoop", "apps", "agy", "current", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", "scoop", "apps", "agy", "current", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "Users", "*", ".local", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "agy", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "agy", "agy.exe"),
                os.path.join(drv, os.sep, "Program Files", "agy", "bin", "agy.exe"),
                os.path.join(drv, os.sep, "Program Files", "agy", "agy.exe"),
            ]
            for pat in patterns:
                for hit in glob.glob(pat):
                    if os.path.isfile(hit):
                        return os.path.abspath(hit)

        # 4. Glob-поиск по всем расширенным candidate_roots
        for root in self._win_candidate_roots():
            hits = glob.glob(os.path.join(root, "*agy*", "bin", "agy.exe"))
            hits += glob.glob(os.path.join(root, "*agy*", "agy.exe"))
            hits += glob.glob(os.path.join(root, "agy", "*", "bin", "agy.exe"))
            hits += glob.glob(os.path.join(root, "bin", "agy.exe"))
            for h in hits:
                if os.path.isfile(h):
                    return os.path.abspath(h)

        # 5. Поиск по запущенному процессу agy
        try:
            ps_cmd = '(Get-Process -Name agy -ErrorAction SilentlyContinue).Path'
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=3)
            out_p = res.stdout.strip()
            if out_p and os.path.isfile(out_p):
                return os.path.abspath(out_p)
        except Exception:
            pass

        return ""

    def find_manager_path(self) -> str:
        """
        Находит путь к language_server.exe (Antigravity 2.0 Desktop) на Windows.
        Ищет:
        0. Пользовательский путь (если задан вручную)
        1. В PATH текущего процесса
        2. Прямым сканированием профилей всех пользователей (C:\\Users\\*\\AppData\\Local\\Programs\\Antigravity\\...)
        3. Через реестр Uninstall (HKLM, HKCU, HKEY_USERS)
        4. Через запущенный процесс Antigravity.exe или language_server.exe
        5. Glob-поиском по candidate_roots
        """
        # 0. Заданный вручную путь
        if self.custom_manager_path and os.path.isfile(self.custom_manager_path):
            return os.path.abspath(self.custom_manager_path)

        # 1. Поиск в PATH
        for binary_name in ("language_server.exe", "language_server"):
            w = shutil.which(binary_name)
            if w and os.path.isfile(w):
                return os.path.abspath(w)

        rel = os.path.join("resources", "bin", "language_server.exe")
        rel_app = os.path.join("resources", "app", "bin", "language_server.exe")

        # 2. Прямой поиск по профилям ВСЕХ пользователей и дискам Windows
        for drv in self._get_fixed_drives():
            patterns = [
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Programs", "Antigravity", rel),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Programs", "Antigravity", rel_app),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Antigravity", rel),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "Programs", "*ntigravity*", rel),
                os.path.join(drv, os.sep, "Users", "*", "AppData", "Local", "*ntigravity*", rel),
                os.path.join(drv, os.sep, "Program Files", "Antigravity", rel),
                os.path.join(drv, os.sep, "Program Files", "*ntigravity*", rel),
                os.path.join(drv, os.sep, "Program Files (x86)", "Antigravity", rel),
                os.path.join(drv, os.sep, "Program Files (x86)", "*ntigravity*", rel),
                os.path.join(drv, os.sep, "Users", "*", "scoop", "apps", "antigravity", "current", rel),
            ]
            for pat in patterns:
                for hit in glob.glob(pat):
                    if os.path.isfile(hit):
                        return os.path.abspath(hit)

        # 3. Поиск через реестр Windows Uninstall (HKCU, HKLM, HKEY_USERS)
        try:
            import winreg
            hives = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
            try:
                with winreg.OpenKey(winreg.HKEY_USERS, "") as u_root:
                    num_subkeys = winreg.QueryInfoKey(u_root)[0]
                    for idx in range(num_subkeys):
                        sid = winreg.EnumKey(u_root, idx)
                        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                            hives.append((winreg.HKEY_USERS, sid))
            except Exception:
                pass

            subkeys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ]
            for hive, prefix in hives:
                for subkey in subkeys:
                    full_key = subkey if prefix in ("HKCU", "HKLM") else rf"{prefix}\{subkey}"
                    try:
                        with winreg.OpenKey(hive, full_key) as key:
                            info = winreg.QueryInfoKey(key)
                            for i in range(info[0]):
                                try:
                                    name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, name) as sub:
                                        disp = ""
                                        try:
                                            disp, _ = winreg.QueryValueEx(sub, "DisplayName")
                                        except OSError:
                                            pass
                                        if disp and "antigravity" in str(disp).lower():
                                            try:
                                                loc, _ = winreg.QueryValueEx(sub, "InstallLocation")
                                                if loc and os.path.isdir(loc):
                                                    for sub_cand in (rel, rel_app):
                                                        cand = os.path.join(loc, sub_cand)
                                                        if os.path.isfile(cand):
                                                            return os.path.abspath(cand)
                                            except OSError:
                                                pass
                                except OSError:
                                    pass
                    except OSError:
                        pass
        except Exception:
            pass

        # 4. Glob поиск по candidate_roots
        for root in self._win_candidate_roots():
            hits = glob.glob(os.path.join(root, "*ntigravity*", rel))
            hits += glob.glob(os.path.join(root, "*ntigravity*", rel_app))
            hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
            for h in hits:
                if os.path.isfile(h):
                    return os.path.abspath(h)

        # 5. Поиск по запущенному процессу (Antigravity.exe или language_server.exe)
        try:
            ps_cmd = '(Get-Process -Name language_server,Antigravity -ErrorAction SilentlyContinue).Path'
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                p = line.strip()
                if not p or not os.path.isfile(p):
                    continue
                if p.lower().endswith("language_server.exe"):
                    return os.path.abspath(p)
                if p.lower().endswith("antigravity.exe"):
                    for sub_cand in (rel, rel_app):
                        cand = os.path.join(os.path.dirname(p), sub_cand)
                        if os.path.isfile(cand):
                            return os.path.abspath(cand)
        except Exception:
            pass

        return ""

    def kill_running_processes(self) -> None:
        """Принудительно закрывает процессы Antigravity и agy на Windows."""
        for name in ("agy.exe", "Antigravity.exe", "language_server.exe", "Antigravity IDE.exe"):
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", name],
                    check=False, capture_output=True, timeout=5
                )
            except Exception:
                pass
        time.sleep(0.5)

    def is_locked(self, path: str) -> bool:
        """Проверяет, заблокирован ли файл работающим процессом."""
        if not path or not os.path.isfile(path):
            return False
        try:
            with open(path, "r+b"):
                return False
        except OSError:
            return True

    def prepare_writable(self, path: str) -> None:
        """Если файл занят процессом, завершает процессы и ожидает снятия блокировки."""
        if self.is_locked(path):
            self.kill_running_processes()
            time.sleep(0.5)

    def post_patch(self, path: str) -> bool:
        """На Windows ad-hoc переподпись бинарников не требуется."""
        return True

    def atomic_replace_file(self, path: str, new_data: bytes) -> None:
        """Безопасная запись/замена файла на Windows с обработкой блокировок."""
        path = os.path.abspath(path)
        self.prepare_writable(path)

        directory = os.path.dirname(path)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(new_data)
                f.flush()
                os.fsync(f.fileno())

            # Попытка атомарной замены через os.replace
            try:
                os.replace(tmp_path, path)
                tmp_path = None
            except OSError:
                # Если os.replace блокируется, пробуем прямую запись
                self.kill_running_processes()
                time.sleep(0.5)
                with open(path, "wb") as f:
                    f.write(new_data)
                    f.flush()
                    os.fsync(f.fileno())
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                tmp_path = None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def get_hosts_path(self) -> str:
        """Путь к файлу hosts на Windows."""
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        return os.path.join(sys_root, "System32", "drivers", "etc", "hosts").replace("/", "\\")

    def read_hosts(self) -> str:
        with open(self.get_hosts_path(), "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def write_hosts(self, new_content: str) -> bool:
        """Запись в C:\\Windows\\System32\\drivers\\etc\\hosts с UAC-повышением при необходимости."""
        hosts_file = self.get_hosts_path()

        # 1. Попытка прямой записи (если скрипт уже запущен от имени Администратора)
        try:
            with open(hosts_file, "w", encoding="utf-8") as f:
                f.write(new_content)
            return True
        except PermissionError:
            pass

        # 2. Если прав не хватило — запуск повышенного процесса копирования через PowerShell UAC (RunAs)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="hosts_tmp_", suffix=".txt")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(new_content)

            # PowerShell запускает cmd copy от имени Администратора (вызов системного окна UAC)
            ps_cmd = (
                f'Start-Process cmd -ArgumentList \'/c copy /y "{tmp_path}" "{hosts_file}"\' '
                f'-Verb RunAs -Wait'
            )
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], check=False, capture_output=True)
            return res.returncode == 0
        except Exception as e:
            log_err(f"Ошибка записи hosts через UAC: {e}")
            return False
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def flush_dns_cache(self) -> None:
        """Сброс кэша DNS в Windows через ipconfig /flushdns."""
        try:
            subprocess.run(["ipconfig", "/flushdns"], check=False, capture_output=True)
            log_ok("Кэш DNS Windows успешно очищен (ipconfig /flushdns).")
        except Exception:
            pass

    def setup_cloud_code_env(self) -> bool:
        """
        Приводит CLOUD_CODE_URL к каноническому значению:
        1. В текущем процессе (os.environ)
        2. В реестре пользователя (HKCU\\Environment) — перезаписывает и
           устаревшие значения старых версий анлокера (например cloudcode-pa,
           на котором agy зависает)
        3. Через setx для всех новых CMD/PowerShell
        """
        target_url = CLOUD_CODE_URL_CANONICAL
        success = False

        # 1. Текущий процесс
        os.environ["CLOUD_CODE_URL"] = target_url

        # 2. Реестр HKCU\Environment (перезаписываем безусловно — это и есть лечение старых значений)
        try:
            import winreg
            prev = ""
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
                    prev, _ = winreg.QueryValueEx(key, "CLOUD_CODE_URL")
            except OSError:
                pass
            if prev and prev != target_url:
                log_warn(f"Найдено устаревшее значение CLOUD_CODE_URL={prev} — перезаписываю на каноническое.")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "CLOUD_CODE_URL", 0, winreg.REG_SZ, target_url)
            success = True
        except Exception:
            pass

        # 3. Команда setx
        try:
            res = subprocess.run(["setx", "CLOUD_CODE_URL", target_url], check=False, capture_output=True, text=True)
            if res.returncode == 0:
                success = True
        except Exception:
            pass

        if success:
            log_ok(f"CLOUD_CODE_URL={target_url} сохранён в профиле Windows (User Environment)!")
            return True
        else:
            log_warn("Не удалось записать CLOUD_CODE_URL в реестр Windows.")
            return False

    def is_cloud_code_env_set(self) -> bool:
        """True, только если эффективное значение равно каноническому."""
        effective, _source, _conflicts = self.get_cloud_code_env_state()
        return effective == CLOUD_CODE_URL_CANONICAL

    def get_cloud_code_env_state(self):
        """(эффективное значение, источник, [(место, значение), ...] конфликты).
        HKCU\Environment для новых процессов приоритетнее HKLM, поэтому
        эффективным считается HKCU (если задан), иначе HKLM, иначе сессия."""
        conflicts = []
        effective, source = "", "не найдено"
        hkcu_val, hklm_val = "", ""
        try:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
                    hkcu_val, _ = winreg.QueryValueEx(key, "CLOUD_CODE_URL")
            except OSError:
                pass
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                                    0, winreg.KEY_READ) as key:
                    hklm_val, _ = winreg.QueryValueEx(key, "CLOUD_CODE_URL")
            except OSError:
                pass
        except Exception:
            pass

        if hklm_val:
            effective, source = hklm_val, "HKLM (системная)"
            if hklm_val != CLOUD_CODE_URL_CANONICAL:
                conflicts.append(("HKLM (системная)", hklm_val))
        if hkcu_val:
            effective, source = hkcu_val, "HKCU\\Environment"
            if hkcu_val != CLOUD_CODE_URL_CANONICAL:
                conflicts.append(("HKCU\\Environment", hkcu_val))
        if os.environ.get("CLOUD_CODE_URL"):
            effective, source = os.environ["CLOUD_CODE_URL"], "текущая сессия"
        return effective, source, conflicts

    def query_udp_dns(self, domain: str, server_ip: str) -> list:
        """Запрос DNS через встроенную в Windows утилиту nslookup."""
        ips = []
        try:
            res = subprocess.run(
                ["nslookup", "-timeout=2", domain, server_ip],
                capture_output=True, text=True, timeout=3
            )
            # Извлекаем все IPv4 из вывода, исключая адрес самого сервера
            found = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", res.stdout)
            for ip in found:
                if ip != server_ip and not ip.startswith("127."):
                    ips.append(ip)
        except Exception:
            pass
        return ips

if __name__ == "__main__":
    # Если запущен напрямую из папки win/
    main_script = os.path.join(parent_dir, "common", "podsoso_obsos.py")
    if os.path.exists(main_script):
        subprocess.run([sys.executable, main_script] + sys.argv[1:])
