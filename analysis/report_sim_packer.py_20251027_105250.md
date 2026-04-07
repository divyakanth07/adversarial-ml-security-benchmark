# Analysis Report: sim_packer.py

- Kind: static
- File Type: Python script
- Size: 487 bytes
- Entropy: 4.9887
- Hashes: MD5=5d3665681bd0e53fbb320abe15fb8528, SHA1=1b0d34c05f3108fb91b085364cd1fb720fcae069, SHA256=11a0728e54f8982d21630861ed0d030589ad3c4528e1fbf58c336e12952b3d7b

## Indicators
- URLs: None
- IPs: None
- Emails: None

## Strings (preview)

- import base64
- import zlib
- PAYLOAD = b"SIM_PACKER: benign payload inside."
- def pack(data: bytes) -> bytes:
-     return base64.b64encode(zlib.compress(data))
- def unpack(blob: bytes) -> bytes:
-     try:
-         return zlib.decompress(base64.b64decode(blob))
-     except Exception:
-         return b""
- if __name__ == "__main__":
-     blob = pack(PAYLOAD)
-     out = unpack(blob)
-     print("SIM_PACKER length:", len(blob))
-     print(out.decode("utf-8", errors="ignore"))