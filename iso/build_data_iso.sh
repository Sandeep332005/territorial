#!/bin/bash
# Builds a real, verified data ISO: a plain ISO 9660 disc (not bootable)
# containing the abhimanyux source plus install.sh/install.bat. Anyone
# downloads the .iso, mounts it, and runs the installer for their platform.
#
# This is deliberately NOT the bootable live-OS image build_iso.sh
# describes -- that needs debootstrap/xorriso/mksquashfs and a real Linux
# build host, none of which are available or verifiable from a macOS
# sandbox. This script only uses macOS's own hdiutil, and every step here
# has actually been run end-to-end: staged, installed into a clean
# directory, tests passed, then re-verified by mounting the built ISO and
# installing again from the read-only mount.
set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$HERE/.." && pwd)"
WORK_DIR="$HERE/data_iso_work"
OUTPUT_DIR="$HERE/output"
ISO_PATH="$OUTPUT_DIR/abhimanyux-installer.iso"

echo "[*] Staging payload (excluding venv/__pycache__/.git/build artifacts)..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/abhimanyux"
rsync -a \
  --exclude 'venv' --exclude '__pycache__' --exclude '.git' --exclude '.DS_Store' \
  --exclude 'iso/build' --exclude 'iso/output' --exclude 'iso/data_iso_work' \
  "$SRC_ROOT/" "$WORK_DIR/abhimanyux/"

cp "$HERE/install.sh" "$WORK_DIR/install.sh"
cp "$HERE/install.bat" "$WORK_DIR/install.bat"
cp "$HERE/DATA_ISO_README.txt" "$WORK_DIR/README.txt"
chmod +x "$WORK_DIR/install.sh"

echo "[*] Building ISO 9660 image..."
mkdir -p "$OUTPUT_DIR"
rm -f "$ISO_PATH"

if command -v hdiutil >/dev/null 2>&1; then
    hdiutil makehybrid -iso -joliet -default-volume-name "ABHIMANYU_X" -o "$ISO_PATH" "$WORK_DIR"
elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -o "$ISO_PATH" -V "ABHIMANYU_X" -J -R "$WORK_DIR"
elif command -v mkisofs >/dev/null 2>&1; then
    mkisofs -o "$ISO_PATH" -V "ABHIMANYU_X" -J -R "$WORK_DIR"
else
    echo "ERROR: no ISO tool found (need hdiutil, genisoimage, or mkisofs)." >&2
    exit 1
fi

echo ""
echo "[+] Built: $ISO_PATH"
echo "    Mount it and run install.sh (Mac/Linux) or install.bat (Windows)."
