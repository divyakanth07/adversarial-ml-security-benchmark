@echo off
echo Safety Checklist:
echo - Use a VM or snapshot; keep offline
echo - Only use 'samples/' provided files; no uploads allowed
echo - Worker runs with --network=none; all runs have 10s timeout
echo - Confirm isolation in the UI before executing

rem Prefer Docker Compose v2 ("docker compose"); fallback to legacy "docker-compose"
docker compose version >nul 2>&1
if %errorlevel%==0 (
  docker compose up --build
  goto :eof
)

where docker-compose >nul 2>&1
if %errorlevel%==0 (
  docker-compose up --build
  goto :eof
)

echo Error: Docker Compose not found. Please start Docker Desktop and ensure "docker compose" works.
exit /b 1


