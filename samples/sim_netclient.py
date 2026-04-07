#!/usr/bin/env python3
import socket

HOST = "127.0.0.1"
PORT = 9009
msg = b"SIM_NET: hello sink from worker."

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        s.sendall(msg)
        print("SIM_NET: sent message")
    except Exception as e:
        print("SIM_NET: connection failed:", e)


