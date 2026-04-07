import base64
import zlib
import os
from pathlib import Path
import secrets
import time

PAYLOAD = b"SIM_PACKER: benign payload inside."
OUT_DIR = Path("sandbox_output")
LOG = OUT_DIR / "packer_analysis.log"
ART_BLOB = OUT_DIR / "packed_blob.bin"
ART_META = OUT_DIR / "packed_blob.meta.txt"

def pack(data: bytes) -> bytes:
    return base64.b64encode(zlib.compress(data))

def unpack(blob: bytes) -> bytes:
    try:
        return zlib.decompress(base64.b64decode(blob))
    except Exception:
        return b""

if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    blob = pack(PAYLOAD + b"\n" + secrets.token_bytes(256))
    # Write packed blob
    ART_BLOB.write_bytes(blob)
    # Attempt unpacking
    out = unpack(blob)
    t1 = time.time()
    # Compute simple entropy estimate
    from math import log2
    freqs = {}
    for b in blob:
        freqs[b] = freqs.get(b, 0) + 1
    length = len(blob) or 1
    entropy = 0.0
    for c in freqs.values():
        p = c / length
        entropy -= p * log2(p)
    entropy = round(entropy, 4)
    # Write metadata to help static analysis demo
    ART_META.write_text(
        "\n".join([
            f"size_bytes={len(blob)}",
            f"entropy={entropy}",
            f"unpacked_preview={out[:64].decode('utf-8', errors='ignore')}",
        ]),
        encoding="utf-8"
    )
    # Log a realistic analysis trail
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"[pack] bytes_in={len(PAYLOAD)} bytes_out={len(blob)} entropy={entropy} dt_ms={int((t1-t0)*1000)}\n")
        f.write(f"[unpack] recovered={len(out)} ok={'yes' if out else 'no'}\n")
    print("SIM_PACKER: wrote sandbox_output/packed_blob.bin and metadata.")


