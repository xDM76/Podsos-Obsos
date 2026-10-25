#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null)"
if [ -z "$PYTHON_BIN" ]; then
    echo "❌ Ошибка: python3 не найден в системе Linux!"
    echo "Установите Python 3 командой:"
    echo "  Ubuntu/Debian: sudo apt update && sudo apt install -y python3"
    echo "  Fedora/RHEL:   sudo dnf install -y python3"
    echo "  Arch Linux:    sudo pacman -S python"
    read -p "Нажмите Enter для выхода..." key
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/common/podsoso_obsos.py" "$@"
