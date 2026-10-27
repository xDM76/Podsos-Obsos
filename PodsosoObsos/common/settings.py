#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  🚀 PodsosoObsos — Settings & Configuration Manager
=============================================================================
  Управление пользовательскими настройками и конфигурацией прокси / анлокера.
  Хранит настройки в JSON-файле:
  - Windows: %LOCALAPPDATA%\\PodsosoObsos\\settings.json (или ~/.podsoso_obsos)
  - macOS / Linux: ~/.podsoso_obsos/settings.json
=============================================================================
"""

import os
import sys
import json

CONFIG_DIR_NAME = ".podsoso_obsos"
SETTINGS_FILE_NAME = "settings.json"

DEFAULT_SETTINGS = {
    "custom_proxy": "",          # URL своего прокси (например, http://127.0.0.1:7890 или socks5://127.0.0.1:10808)
    "proxy_port": 53129,         # Порт локального прокси
    "mode": "auto",              # "auto" (свой прокси если задан, иначе умный DoH SNI), "custom", "sni", "direct"
    "last_confirmed_route": "",  # Последний маршрут, подтверждённый успешным ответом модели
    "autostart": False           # Автозапуск службы прокси при входе в систему
}

def get_config_dir() -> str:
    """Возвращает путь к директории конфигурации для текущей платформы."""
    if sys.platform == "win32" or os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("USERPROFILE") or os.path.expanduser("~")
        cfg_dir = os.path.join(base, "PodsosoObsos")
    else:
        cfg_dir = os.path.expanduser(f"~/{CONFIG_DIR_NAME}")
    
    os.makedirs(cfg_dir, exist_ok=True)
    return cfg_dir

def get_settings_file() -> str:
    return os.path.join(get_config_dir(), SETTINGS_FILE_NAME)

def load_settings() -> dict:
    path = get_settings_file()
    if not os.path.isfile(path):
        return dict(DEFAULT_SETTINGS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = dict(DEFAULT_SETTINGS)
            merged.update(data)
            return merged
    except Exception:
        return dict(DEFAULT_SETTINGS)

def save_settings(data: dict) -> bool:
    path = get_settings_file()
    try:
        merged = load_settings()
        merged.update(data)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Ошибка сохранения настроек: {e}", file=sys.stderr)
        return False

def get_custom_proxy() -> str:
    return load_settings().get("custom_proxy", "").strip()

def set_custom_proxy(proxy_url: str) -> bool:
    return save_settings({"custom_proxy": proxy_url.strip()})

def get_proxy_port() -> int:
    return int(load_settings().get("proxy_port", 53129))

def set_proxy_port(port: int) -> bool:
    return save_settings({"proxy_port": int(port)})
