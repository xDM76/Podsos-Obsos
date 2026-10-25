#!/bin/zsh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="$(command -v python3 2>/dev/null)"
if [ -z "$PYTHON_BIN" ]; then
    echo "❌ Ошибка: python3 не найден в системе macOS!"
    echo "Установите Xcode Command Line Tools командой: xcode-select --install"
    read -p "Нажмите Enter для выхода..." key
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/common/podsoso_obsos.py" "$@"
