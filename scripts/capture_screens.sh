#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-screens}
BASE_URL=${2:-http://localhost:5000}

mkdir -p "$OUT_DIR"

CHROME_BIN=${CHROME_BIN:-}
if command -v google-chrome >/dev/null 2>&1; then CHROME_BIN=$(command -v google-chrome); fi
if command -v chromium >/dev/null 2>&1; then CHROME_BIN=$(command -v chromium); fi
if command -v chromium-browser >/dev/null 2>&1; then CHROME_BIN=$(command -v chromium-browser); fi

if [ -z "$CHROME_BIN" ]; then
  echo "ERROR: Chrome/Chromium not found. Set CHROME_BIN or install chromium." >&2
  exit 1
fi

function shot() {
  local name="$1"; shift
  local url="$1"; shift
  "$CHROME_BIN" \
    --headless=new \
    --disable-gpu \
    --window-size=1280,800 \
    --screenshot="$OUT_DIR/${name}.png" \
    "$url"
}

shot home        "$BASE_URL/#home"
shot samples     "$BASE_URL/#samples"
shot static      "$BASE_URL/#static"
shot deepstatic  "$BASE_URL/#deepstatic"
shot dynamic     "$BASE_URL/#dynamic"
shot network     "$BASE_URL/#network"
shot yara        "$BASE_URL/#yara"
shot reports     "$BASE_URL/#reports"

echo "Screenshots saved to $OUT_DIR"


