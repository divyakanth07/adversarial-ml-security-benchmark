#!/usr/bin/env bash
set -euo pipefail

SRC_DIR=${1:-screens}
OUT_GIF=${2:-demo.gif}

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ERROR: ffmpeg not found. Install ffmpeg to create GIFs." >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Create a simple slideshow video from PNGs
ls "$SRC_DIR"/*.png | sort | awk '{print "file '"$0"'\n duration 1.2"}' > "$tmp/list.txt"
tail -n1 "$tmp/list.txt" | sed 's/duration.*/duration 2.5/' -i || true

ffmpeg -y -f concat -safe 0 -i "$tmp/list.txt" -vf "fps=10,scale=1024:-1:flags=lanczos" -loop 0 "$OUT_GIF"

echo "GIF saved to $OUT_GIF"


