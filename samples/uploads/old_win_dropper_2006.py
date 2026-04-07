# old_win_dropper_2006.py (synthetic, benign)
import os, sys, base64, socket, time

C2_URLS = [
    "http://update.old-malware-example.com/check",
    "http://example.bad/updates",
]
C2_IPS = [
    "212.71.250.12",
    "10.0.2.15",
]
REG_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]
EMAILS = ["support@old-malware-example.com", "admin@criminals.biz"]

# Dummy obfuscation routine (unused, for static AST and strings)
def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes([(b ^ key) for b in data])

PAYLOAD_B64 = "IyB0aGlzIGlzIG5vdCBhIHJlYWwgcGF5bG9hZC4uLg=="

def main():
    print("Synthetic vintage-style dropper mimic (benign).")
    print("C2_URLS:", ", ".join(C2_URLS))
    print("C2_IPS:", ", ".join(C2_IPS))
    print("REG_KEYS:", ", ".join(REG_KEYS))
    # Decode a benign base64 blob to trigger string/entropy/AST paths
    _ = base64.b64decode(PAYLOAD_B64)
    time.sleep(0.1)

if __name__ == "__main__":
    main()