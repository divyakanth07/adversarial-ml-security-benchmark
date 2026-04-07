#!/usr/bin/env bash
set -euo pipefail

cat <<EOF
Safety Checklist:
- Use a VM or snapshot; keep offline
- Only use 'samples/' provided files; no uploads allowed
- Worker runs with --network=none; all runs have 10s timeout
- Confirm isolation in the UI before executing
EOF

docker-compose up --build


