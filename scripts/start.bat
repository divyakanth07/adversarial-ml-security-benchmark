@echo off
echo Safety Checklist:
echo - Use a VM or snapshot; keep offline
echo - Only use 'samples/' provided files; no uploads allowed
echo - Worker runs with --network=none; all runs have 10s timeout
echo - Confirm isolation in the UI before executing

docker-compose up --build


