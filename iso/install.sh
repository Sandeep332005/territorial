#!/bin/bash
# Abhimanyu X installer (Mac/Linux). Run from the mounted ISO:
#   ./install.sh [target-directory, default: ~/abhimanyux-install]
set -e

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-$HOME/abhimanyux-install}"

echo "============================================================"
echo "Abhimanyu X - Installer"
echo "============================================================"
echo "Installing to: $TARGET"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found on PATH. Install Python 3.10+ first." >&2
    exit 1
fi

mkdir -p "$TARGET"
cp -R "$SRC_DIR/abhimanyux" "$TARGET/"

cd "$TARGET/abhimanyux"
echo "[*] Creating virtual environment..."
python3 -m venv venv
echo "[*] Installing dependencies..."
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q -r requirements.txt

cat <<EOF

Installed: $TARGET/abhimanyux

Next steps:

  1. Install Ollama (https://ollama.com) and pull a local model:
       ollama pull dolphin-llama3:8b

  2. Scan a file or directory:
       cd $TARGET
       PYTHONPATH=. abhimanyux/venv/bin/python -m abhimanyux.core.orchestrator <target>

  3. Confirm the install works (runs the real test suite):
       cd $TARGET
       PYTHONPATH=. abhimanyux/venv/bin/python -m pytest abhimanyux/tests/ -q

Note: this installs the source and its Python dependencies. It does not
install Ollama or a language model for you -- ANVIL's patch generation
needs one of those configured separately (see abhimanyux/README.md).
EOF
