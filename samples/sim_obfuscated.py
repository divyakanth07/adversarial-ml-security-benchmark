import base64
import time
from pathlib import Path

# Two-layer benign obfuscation: base64 of hex-encoded ASCII
_L1 = "53554d3a2053696d756c6174656420494f437320666f722064656d6f2e"  # "SUM: Simulated IOCs for demo."
_L2 = base64.b64encode(bytes.fromhex(_L1)).decode("ascii")

OUT_DIR = Path("sandbox_output")
LOG = OUT_DIR / "obfuscated_deob.log"
ART_IOCS = OUT_DIR / "ioc_list.txt"

def deobfuscate() -> str:
    t0 = time.time()
    raw = base64.b64decode(_L2)
    text = raw.decode("utf-8", errors="ignore")
    dt_ms = int((time.time() - t0) * 1000)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"[stage1] b64->bytes len={len(raw)} dt_ms={dt_ms}\n")
    return text

def write_iocs(message: str) -> None:
    # Simulated indicators derived from deobfuscated content
    urls = [
        "http://example.local/update",
        "https://intranet.local/api",
    ]
    ips = ["10.0.0.5", "127.0.0.1"]
    with ART_IOCS.open("w", encoding="utf-8") as f:
        f.write("message=" + message + "\n")
        f.write("urls=" + ",".join(urls) + "\n")
        f.write("ips=" + ",".join(ips) + "\n")
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"[iocs] wrote {ART_IOCS.name} with {len(urls)} urls and {len(ips)} ips\n")

if __name__ == "__main__":
    msg = deobfuscate()
    write_iocs(msg)
    print("SIM_OBFUSCATED: deobfuscated and wrote sandbox_output/ioc_list.txt.")


