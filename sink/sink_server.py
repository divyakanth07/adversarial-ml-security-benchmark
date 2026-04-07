#!/usr/bin/env python3
import socket
import os
from pathlib import Path

HOST = "127.0.0.1"
PORT = 9009
LOG_DIR = Path("/workspace/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "captured_messages.log"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            if data:
                with LOG_FILE.open("a", encoding="utf-8") as f:
                    f.write(data.decode("utf-8", errors="ignore") + "\n")


