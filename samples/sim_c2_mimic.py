#!/usr/bin/env python3
import os
import sys
import time
import base64
import hashlib

# Synthetic, benign sample that mimics common vintage malware traits for static analysis
C2_DOMAINS = [
    "update.old-malware-example.com",
    "cdn.legacy-botnet.biz",
]

C2_URLS = [
    "http://update.old-malware-example.com/check",
    "http://cdn.legacy-botnet.biz/payload",
]

C2_IPS = [
    "94.23.12.10",
    "51.38.42.77",
]

REGISTRY_PATHS = [
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

EMAILS = [
    "support@old-malware-example.com",
    "admin@legacy-botnet.biz",
]

USER_AGENT = "Mozilla/5.0 (Windows NT 5.1; Trident/4.0)"


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes((b ^ (key & 0xFF)) for b in data)


# Benign payload blob to trigger entropy/string/AST paths
PAYLOAD_B64 = "VGhpcyBpcyBhIGJlbmlnbiBwbGFjZWhvbGRlciBzYW1wbGUu"  # "This is a benign placeholder sample."


def write_artifact(text: str) -> None:
    out_dir = os.path.join(os.getcwd(), "sandbox_output")
    try:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "vintage_c2_marker.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


def main() -> int:
    print("SIM_C2_MIMIC: benign synthetic sample")
    print("C2_DOMAINS:", ", ".join(C2_DOMAINS))
    print("C2_URLS:", ", ".join(C2_URLS))
    print("C2_IPS:", ", ".join(C2_IPS))
    print("REGISTRY_PATHS:", ", ".join(REGISTRY_PATHS))
    print("EMAILS:", ", ".join(EMAILS))
    print("USER_AGENT:", USER_AGENT)

    blob = base64.b64decode(PAYLOAD_B64)
    md5 = hashlib.md5(blob).hexdigest()
    print("BLOB_MD5:", md5)

    # Unused XOR to expose function and suspicious-looking routine
    _ = xor_bytes(blob, 0x5A)

    write_artifact(f"SIM_C2_MIMIC artifact md5={md5}\n")
    time.sleep(0.1)
    return 0


if __name__ == "__main__":
    sys.exit(main())


