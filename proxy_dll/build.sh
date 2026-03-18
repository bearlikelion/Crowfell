#!/bin/bash
# Build version.dll proxy with MinGW
# Output goes to the game directory for easy testing
set -e

GAME_DIR="/mnt/Storage/Crowfall/Client/Download"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building version.dll proxy..."
x86_64-w64-mingw32-gcc \
    -shared \
    -o "$SCRIPT_DIR/version.dll" \
    "$SCRIPT_DIR/version.c" \
    "$SCRIPT_DIR/version.def" \
    -lkernel32 -luser32 \
    -O2 -s \
    -Wall -Wextra

echo "Built: $SCRIPT_DIR/version.dll"
echo ""
echo "To install, copy to the game directory:"
echo "  cp \"$SCRIPT_DIR/version.dll\" \"$GAME_DIR/version.dll\""
echo ""
echo "To uninstall, just delete it:"
echo "  rm \"$GAME_DIR/version.dll\""
echo ""
echo "Logs go to: $GAME_DIR/crowfall_proxy.log"
