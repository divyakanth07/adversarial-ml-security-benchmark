import os
import ast
import re
import io
import json
import zipfile
import subprocess
import shutil
import hashlib
import math
from datetime import datetime
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from html import escape as html_escape

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# Prefer the bind-mounted workspace if present (shared with worker); fallback to repo of this file
MOUNTED_WORKSPACE = Path("/workspace")
REPO_ROOT = MOUNTED_WORKSPACE if MOUNTED_WORKSPACE.exists() else Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"
LOGS_DIR = REPO_ROOT / "logs"
YARA_DIR = REPO_ROOT / "yara"
UPLOADS_DIR = SAMPLES_DIR / "uploads"

LOGS_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

SAFE_SAMPLES = {
    "sim_print.py": {"type": "python", "path": SAMPLES_DIR / "sim_print.py"},
    "sim_dropper.c": {"type": "c", "path": SAMPLES_DIR / "sim_dropper.c"},
    "sim_netclient.py": {"type": "python", "path": SAMPLES_DIR / "sim_netclient.py"},
    "compiled/sim_dropper": {"type": "binary", "path": SAMPLES_DIR / "compiled" / "sim_dropper"},
    "sim_packer.py": {"type": "python", "path": SAMPLES_DIR / "sim_packer.py"},
    "sim_persistence.py": {"type": "python", "path": SAMPLES_DIR / "sim_persistence.py"},
    "sim_obfuscated.py": {"type": "python", "path": SAMPLES_DIR / "sim_obfuscated.py"},
    "sim_c2_mimic.py": {"type": "python", "path": SAMPLES_DIR / "sim_c2_mimic.py"},
    "sim_elf_mimic.c": {"type": "c", "path": SAMPLES_DIR / "sim_elf_mimic.c"},
    "compiled/sim_elf_mimic": {"type": "binary", "path": SAMPLES_DIR / "compiled" / "sim_elf_mimic"},
}

WORKER_CONTAINER = "malware_worker"
WORKDIR_IN_WORKER = "/workspace/samples"
NONROOT_USER = "worker_user"
DEFAULT_TIMEOUT = 10
ULIMIT_VMEM_KB = 262144

app = Flask(__name__, static_folder=str(REPO_ROOT / "frontend"), static_url_path="")
CORS(app)


def build_worker_exec(prefix_cmd: str, detach: bool = False) -> List[str]:
    base = [
        "docker", "exec",
        "--user", NONROOT_USER,
        "--workdir", WORKDIR_IN_WORKER,
    ]
    if detach:
        base.insert(2, "-d")
    full = base + [
        WORKER_CONTAINER, "bash", "-lc",
        f"ulimit -t {DEFAULT_TIMEOUT}; ulimit -v {ULIMIT_VMEM_KB}; timeout {DEFAULT_TIMEOUT}s {prefix_cmd}"
    ]
    return full


def run_in_worker(command: str, capture_output: bool = True) -> Tuple[int, str, str]:
    exec_cmd = build_worker_exec(command, detach=False)
    try:
        result = subprocess.run(
            exec_cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return result.returncode, stdout, stderr
    except FileNotFoundError as e:
        return 127, "", str(e)


def run_in_worker_detached(command: str) -> int:
    base = [
        "docker", "exec",
        "-d",
        "--user", NONROOT_USER,
        "--workdir", WORKDIR_IN_WORKER,
        WORKER_CONTAINER, "bash", "-lc",
        command
    ]
    try:
        result = subprocess.run(base)
        return result.returncode
    except FileNotFoundError:
        return 127


def list_artifacts() -> Dict[str, List[str]]:
    compiled_dir = SAMPLES_DIR / "compiled"
    output_dir = SAMPLES_DIR / "sandbox_output"
    compiled = []
    dropped = []
    if compiled_dir.exists():
        for p in compiled_dir.glob("*"):
            if p.is_file():
                compiled.append(str(p.relative_to(SAMPLES_DIR)))
    if output_dir.exists():
        for p in output_dir.glob("**/*"):
            if p.is_file():
                dropped.append(str(p.relative_to(SAMPLES_DIR)))
    return {"compiled": sorted(compiled), "sandbox_output": sorted(dropped)}


def read_sandbox_output_previews(max_bytes: int = 8192) -> Dict[str, Dict[str, object]]:
    """Return previews of sandbox_output files: {rel_path: {size, preview}}"""
    output_dir = SAMPLES_DIR / "sandbox_output"
    previews: Dict[str, Dict[str, object]] = {}
    if not output_dir.exists():
        return previews
    for p in output_dir.glob("**/*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(SAMPLES_DIR))
        try:
            data = p.read_bytes()
            preview = data[:max_bytes].decode("utf-8", errors="replace")
            previews[rel] = {
                "size": p.stat().st_size,
                "preview": preview,
            }
        except Exception:
            previews[rel] = {
                "size": p.stat().st_size if p.exists() else 0,
                "preview": "(unable to read)",
            }
    return previews


def list_uploads() -> List[str]:
    files: List[str] = []
    if UPLOADS_DIR.exists():
        for p in UPLOADS_DIR.glob("**/*"):
            if p.is_file():
                files.append(str(p.relative_to(SAMPLES_DIR)))
    return sorted(files)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs: Dict[int, int] = {}
    for b in data:
        freqs[b] = freqs.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freqs.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_file_type(path: Path, data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "ELF binary"
    if data[:2] == b"MZ":
        return "PE (Windows)"
    if data.startswith(b"#!"):
        return "Script (shebang)"
    if path.suffix.lower() == ".py":
        return "Python script"
    if os.access(path, os.X_OK):
        return "Executable file"
    return f"{path.suffix.lower()} file" if path.suffix else "Unknown"


def extract_urls_ips(text: str) -> Dict[str, List[str]]:
    url_re = re.compile(r"\bhttps?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    emails_re = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
    urls = sorted(set(url_re.findall(text)))
    ips = sorted(set(ip_re.findall(text)))
    emails = sorted(set(emails_re.findall(text)))
    return {"urls": urls, "ips": ips, "emails": emails}


def extract_python_imports(text: str) -> List[str]:
    imports: List[str] = []
    for line in text.splitlines():
        m = re.match(r"^\s*from\s+([\w\.]+)\s+import\b", line)
        if m:
            imports.append(m.group(1))
            continue
        m = re.match(r"^\s*import\s+([\w\.,\s]+)$", line)
        if m:
            mods = [s.strip() for s in m.group(1).split(',') if s.strip()]
            imports.extend(mods)
    return sorted(set(imports))


def safe_sample_path(sample: str) -> Optional[Path]:
    if sample in SAFE_SAMPLES:
        return SAFE_SAMPLES[sample]["path"]
    p = (SAMPLES_DIR / sample).resolve()
    try:
        uploads_root = UPLOADS_DIR.resolve()
    except Exception:
        return None
    if str(p).startswith(str(uploads_root)) and p.exists() and p.is_file():
        return p
    p2 = (UPLOADS_DIR / os.path.basename(sample)).resolve()
    if p2.exists() and p2.is_file() and str(p2).startswith(str(uploads_root)):
        return p2
    return None


def extract_strings(path: Path, min_len: int = 4) -> List[str]:
    printable = re.compile(rb"[ -~]{%d,}" % min_len)
    try:
        data = path.read_bytes()
    except Exception:
        return []
    return [s.decode("utf-8", errors="ignore") for s in printable.findall(data)]


def try_run_local(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except Exception as ex:
        return 127, "", str(ex)


def analyze_python_source(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"imports": [], "functions": [], "classes": []}
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out["imports"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    out["imports"].append(node.module)
            elif isinstance(node, ast.FunctionDef):
                out["functions"].append(node.name)
            elif isinstance(node, ast.ClassDef):
                out["classes"].append(node.name)
    except Exception:
        pass
    out["imports"] = sorted(set(out["imports"]))
    out["functions"] = sorted(set(out["functions"]))
    out["classes"] = sorted(set(out["classes"]))
    return out


def analyze_binary_with_objdump(path: Path) -> Dict[str, object]:
    info: Dict[str, object] = {"tool": "objdump", "available": False}
    objdump = shutil.which("objdump")
    if not objdump:
        return info
    code, out, err = try_run_local([objdump, "-x", str(path)])
    if code != 0:
        info.update({"available": True, "error": (err or out).strip()[:5000]})
        return info
    info["available"] = True
    headers: Dict[str, str] = {}
    sections: List[Dict[str, str]] = []
    imports: List[str] = []
    exports: List[str] = []
    mode = "headers"
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("Sections:"):
            mode = "sections"
            continue
        if s.startswith("Import") or s.startswith("Dynamic Section"):
            mode = "imports"
        if s.startswith("SYMBOL TABLE"):
            mode = "symbols"
        if mode == "headers":
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip()] = v.strip()
        elif mode == "sections":
            # crude split of section table rows
            parts = s.split()
            if len(parts) >= 6 and parts[0].isdigit() is False:
                sections.append({"name": parts[0], "addr": parts[1], "size": parts[2]})
        elif mode == "imports":
            if ":" in s:
                lib = s.split(":", 1)[0].strip()
                if lib and lib not in imports:
                    imports.append(lib)
        elif mode == "symbols":
            # collect potential exported symbols (very rough)
            if s.endswith(".globl"):
                exports.append(s)
    info.update({
        "headers": headers,
        "sections": sections[:200],
        "imports": imports[:200],
        "exports_sample": exports[:200],
    })
    return info


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.get("/analysis/<path:filename>")
def serve_analysis(filename: str):
    target = REPO_ROOT / "analysis" / filename
    if not target.exists():
        return jsonify({"error": "file not found"}), 404
    return send_file(str(target), as_attachment=True)


@app.get("/api/samples")
def api_samples():
    samples_meta = []
    for name, meta in SAFE_SAMPLES.items():
        exists = meta["path"].exists()
        samples_meta.append({
            "name": name,
            "type": meta["type"],
            "exists": exists
        })
    for rel in list_uploads():
        samples_meta.append({
            "name": rel,
            "type": "upload",
            "exists": True
        })
    return jsonify({
        "samples": samples_meta,
        "artifacts": list_artifacts(),
        "sandbox_output_contents": read_sandbox_output_previews(),
        "notes": "Only whitelisted samples can be compiled or run."
    })


@app.post("/api/compile")
def api_compile():
    payload = request.get_json(silent=True) or {}
    sample = payload.get("sample")
    if sample not in ("sim_dropper.c", "sim_elf_mimic.c"):
        return jsonify({"error": "Only 'sim_dropper.c' or 'sim_elf_mimic.c' can be compiled."}), 400
    meta = SAFE_SAMPLES.get(sample)
    if not meta or not meta["path"].exists():
        return jsonify({"error": "Sample not found."}), 404

    if sample == "sim_dropper.c":
        cmd = "mkdir -p compiled sandbox_output && gcc sim_dropper.c -o compiled/sim_dropper"
    else:
        cmd = "mkdir -p compiled sandbox_output && gcc sim_elf_mimic.c -o compiled/sim_elf_mimic"
    code, out, err = run_in_worker(cmd)
    # Local fallback when Docker CLI is missing
    if code == 127 or ("docker" in (err or "").lower()):
        gcc = shutil.which("gcc")
        try:
            if gcc:
                (SAMPLES_DIR / "compiled").mkdir(parents=True, exist_ok=True)
                compile_args = [gcc]
                if sample == "sim_dropper.c":
                    compile_args += ["sim_dropper.c", "-o", "compiled/sim_dropper"]
                else:
                    compile_args += ["sim_elf_mimic.c", "-o", "compiled/sim_elf_mimic"]
                result = subprocess.run(
                    compile_args,
                    cwd=str(SAMPLES_DIR),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=DEFAULT_TIMEOUT,
                )
                code, out, err = result.returncode, result.stdout or "", result.stderr or ""
        except Exception as ex:
            err = f"local-fallback-error: {ex}"
    artifacts = list_artifacts()
    return jsonify({
        "returncode": code,
        "stdout": out,
        "stderr": err,
        "artifacts": artifacts
    }), (200 if code == 0 else 500)


@app.post("/api/run")
def api_run():
    payload = request.get_json(silent=True) or {}
    sample = payload.get("sample")
    if sample not in SAFE_SAMPLES:
        return jsonify({"error": "Sample not allowed."}), 400
    meta = SAFE_SAMPLES[sample]
    if not meta["path"].exists():
        return jsonify({"error": "Sample not found on disk."}), 404

    if sample == "sim_print.py":
        cmd = "python3 sim_print.py"
    elif sample == "compiled/sim_dropper":
        cmd = "./compiled/sim_dropper"
    elif sample == "sim_netclient.py":
        cmd = "python3 sim_netclient.py"
    elif sample == "sim_packer.py":
        cmd = "python3 sim_packer.py"
    elif sample == "sim_persistence.py":
        cmd = "python3 sim_persistence.py"
    elif sample == "sim_obfuscated.py":
        cmd = "python3 sim_obfuscated.py"
    elif sample == "sim_c2_mimic.py":
        cmd = "python3 sim_c2_mimic.py"
    elif sample == "compiled/sim_elf_mimic":
        cmd = "./compiled/sim_elf_mimic"
    else:
        return jsonify({"error": "Unsupported sample."}), 400

    code, out, err = run_in_worker(cmd)
    # Local fallback when Docker CLI is missing or worker unavailable
    err_l = (err or "").lower()
    if code == 127 or ("docker" in err_l) or ("no such container" in err_l) or ("is not running" in err_l) or ("cannot connect to the docker daemon" in err_l):
        try:
            if sample in ("sim_print.py", "sim_netclient.py", "sim_packer.py", "sim_persistence.py", "sim_obfuscated.py", "sim_c2_mimic.py"):
                python_exec = shutil.which("python3") or shutil.which("python") or "python3"
                result = subprocess.run(
                    [python_exec, sample],
                    cwd=str(SAMPLES_DIR),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=DEFAULT_TIMEOUT,
                )
                code, out, err = result.returncode, result.stdout or "", result.stderr or ""
            elif sample in ("compiled/sim_dropper", "compiled/sim_elf_mimic"):
                local_bin = SAMPLES_DIR / ("compiled/sim_dropper" if sample == "compiled/sim_dropper" else "compiled/sim_elf_mimic")
                if local_bin.exists():
                    result = subprocess.run(
                        [str(local_bin)],
                        cwd=str(SAMPLES_DIR),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=DEFAULT_TIMEOUT,
                    )
                    code, out, err = result.returncode, result.stdout or "", result.stderr or ""
        except Exception as ex:
            err = f"local-fallback-error: {ex}"
    # Persist outputs to sandbox_output for artifacts view
    try:
        (SAMPLES_DIR / "sandbox_output").mkdir(parents=True, exist_ok=True)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", sample)
        base = SAMPLES_DIR / "sandbox_output" / f"run_{safe_name}_{now}"
        (base.parent).mkdir(parents=True, exist_ok=True)
        (Path(str(base) + ".stdout.txt")).write_text(out or "", encoding="utf-8", errors="ignore")
        (Path(str(base) + ".stderr.txt")).write_text(err or "", encoding="utf-8", errors="ignore")
    except Exception:
        pass
    artifacts = list_artifacts()
    (LOGS_DIR / "run_history.log").open("a", encoding="utf-8").write(
        json.dumps({"sample": sample, "returncode": code}) + "\n"
    )
    return jsonify({
        "sample": sample,
        "returncode": code,
        "stdout": out,
        "stderr": err,
        "artifacts": artifacts
    }), (200 if code == 0 else 500)


@app.get("/api/static")
def api_static_analysis():
    sample = request.args.get("sample", "")
    path = safe_sample_path(sample)
    if not path:
        return jsonify({"error": "Sample not allowed for static analysis."}), 400
    if not path.exists():
        return jsonify({"error": "Sample not found on disk."}), 404
    try:
        data = path.read_bytes()
    except Exception:
        data = b""
    size = path.stat().st_size if path.exists() else 0
    strings = extract_strings(path, min_len=4)
    hashes = compute_hashes(data) if data else {"md5": "", "sha1": "", "sha256": ""}
    ftype = detect_file_type(path, data)
    ent = shannon_entropy(data)
    findings = extract_urls_ips(data.decode("utf-8", errors="ignore"))
    py_imports: List[str] = []
    if path.suffix.lower() == ".py":
        py_imports = extract_python_imports(data.decode("utf-8", errors="ignore"))
    head_hex = data[:64].hex()
    return jsonify({
        "sample": sample,
        "exists": True,
        "size_bytes": size,
        "type": ftype,
        "hashes": hashes,
        "entropy": ent,
        "urls": findings.get("urls", []),
        "ips": findings.get("ips", []),
        "emails": findings.get("emails", []),
        "python_imports": py_imports,
        "strings_preview": strings[:50],
        "hex_head_64": head_hex,
    })


@app.get("/api/deep_static")
def api_deep_static():
    sample = request.args.get("sample", "")
    path = safe_sample_path(sample)
    if not path:
        return jsonify({"error": "Sample not allowed for static analysis."}), 400
    if not path.exists():
        return jsonify({"error": "Sample not found on disk."}), 404
    try:
        data = path.read_bytes()
    except Exception:
        data = b""

    base = {
        "sample": sample,
        "exists": True,
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "hashes": compute_hashes(data) if data else {"md5": "", "sha1": "", "sha256": ""},
        "entropy": shannon_entropy(data),
        "type": detect_file_type(path, data),
    }

    details: Dict[str, object] = {}
    text_preview = data[:4096].decode("utf-8", errors="ignore") if data else ""
    details["urls_ips_emails"] = extract_urls_ips(text_preview)
    details["strings"] = extract_strings(path, min_len=5)[:200]
    if path.suffix.lower() == ".py":
        details["python_ast"] = analyze_python_source(text_preview)
    # Try objdump for binaries/scripts with shebangs or exec bit
    try_objdump = os.access(path, os.X_OK) or path.suffix.lower() in ("", ".out", ".exe", ".bin") or data[:4] in (b"\x7fELF", b"MZ")
    if try_objdump:
        details["objdump"] = analyze_binary_with_objdump(path)

    return jsonify({**base, "details": details})


@app.get("/api/logs")
def api_logs():
    log_path = LOGS_DIR / "captured_messages.log"
    if not log_path.exists():
        return jsonify({"log": "", "note": "No messages yet."})
    return jsonify({"log": log_path.read_text(encoding="utf-8", errors="ignore")})


@app.post("/api/sink/start")
def api_sink_start():
    (LOGS_DIR).mkdir(parents=True, exist_ok=True)
    cmd = f"mkdir -p /workspace/logs && python3 /workspace/sink/sink_server.py"
    rc = run_in_worker_detached(cmd)
    if rc == 0:
        return jsonify({"status": "started", "mode": "worker", "returncode": rc})

    # Local fallback when Docker CLI is missing or worker not running
    py = shutil.which("python3") or shutil.which("python") or sys.executable or "python3"
    sink_py = REPO_ROOT / "sink" / "sink_server.py"
    stdout_path = LOGS_DIR / "sink_stdout.log"
    stderr_path = LOGS_DIR / "sink_stderr.log"
    creationflags = 0
    popen_kwargs = {}
    try:
        if os.name == "nt":
            # Detach on Windows
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            popen_kwargs["creationflags"] = creationflags
        else:
            popen_kwargs["start_new_session"] = True
        with open(stdout_path, "ab", buffering=0) as out, open(stderr_path, "ab", buffering=0) as err:
            p = subprocess.Popen([py, str(sink_py)], cwd=str(REPO_ROOT), stdout=out, stderr=err, **popen_kwargs)
        return jsonify({"status": "started", "mode": "local", "note": "Docker unavailable; started locally.", "returncode": rc})
    except Exception as ex:
        return jsonify({"status": "failed", "returncode": rc, "error": str(ex)}), 500


@app.post("/api/yara")
def api_yara():
    rules_path = f"/workspace/yara/sim_rules.yar"
    target_path = f"/workspace/samples"
    code, out, err = run_in_worker(f"yara -r {rules_path} {target_path} || true")
    out = out.strip()
    if out:
        return jsonify({"engine": "yara", "output": out})
    hits = []
    sigs = [b"SIM_PRINT", b"SIM_DROPPER", b"SIM_NET"]
    for rel, meta in SAFE_SAMPLES.items():
        p = meta["path"]
        if p.exists() and p.is_file():
            data = p.read_bytes()
            if any(sig in data for sig in sigs):
                hits.append(rel)
    return jsonify({"engine": "simulate", "output": "\n".join(hits)})


@app.post("/api/upload")
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    f = request.files["file"]
    if f.filename is None or f.filename.strip() == "":
        return jsonify({"error": "Empty filename"}), 400
    name = os.path.basename(f.filename)
    target = UPLOADS_DIR / name
    target.parent.mkdir(parents=True, exist_ok=True)
    f.save(str(target))
    return jsonify({"saved_as": str(target.relative_to(SAMPLES_DIR)), "size": target.stat().st_size})


@app.post("/api/report")
def api_report():
    payload = request.get_json(silent=True) or {}
    sample = payload.get("sample", "")
    analysis_kind = payload.get("kind", "static")
    out_format = (payload.get("format", "md") or "md").lower()
    path = safe_sample_path(sample)
    if not path:
        return jsonify({"error": "Sample not allowed for reporting."}), 400
    try:
        data = path.read_bytes()
    except Exception:
        data = b""
    hashes = compute_hashes(data) if data else {"md5": "", "sha1": "", "sha256": ""}
    ent = shannon_entropy(data)
    ftype = detect_file_type(path, data)
    findings = extract_urls_ips(data.decode("utf-8", errors="ignore"))
    strings = extract_strings(path)[:50]
    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(sample) or "sample")

    # Ensure analysis dir exists
    (REPO_ROOT / "analysis").mkdir(parents=True, exist_ok=True)

    if out_format == "html" or out_format == "pdf":
        # Build simple HTML content
        title = f"Analysis Report: {html_escape(sample)}"
        details = {
            "Kind": analysis_kind,
            "File Type": ftype,
            "Size": f"{path.stat().st_size if path.exists() else 0} bytes",
            "Entropy": str(ent),
            "MD5": hashes.get("md5", ""),
            "SHA1": hashes.get("sha1", ""),
            "SHA256": hashes.get("sha256", ""),
        }
        indicators_html = "".join([
            f"<li><strong>URLs</strong>: {html_escape(', '.join(findings.get('urls', [])) or 'None')}</li>",
            f"<li><strong>IPs</strong>: {html_escape(', '.join(findings.get('ips', [])) or 'None')}</li>",
            f"<li><strong>Emails</strong>: {html_escape(', '.join(findings.get('emails', [])) or 'None')}</li>",
        ])
        strings_html = "".join([f"<li>{html_escape(s)}</li>" for s in strings]) or "<em>(no printable strings)</em>"
        rows = "".join([f"<tr><th>{html_escape(k)}</th><td>{html_escape(v)}</td></tr>" for k, v in details.items()])
        html_content = (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\"/>\n"
            f"<title>{title}</title>\n"
            "<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px;} h1{margin-top:0;} table{border-collapse:collapse;width:100%;max-width:900px;} th,td{border:1px solid #ddd;padding:8px;text-align:left;} th{background:#f3f4f6;width:180px;} ul{padding-left:18px;} .section{margin-top:20px;} .muted{color:#6b7280;}</style>\n"
            "</head>\n<body>\n"
            f"<h1>{title}</h1>\n"
            f"<div class=\"muted\">Generated: {now} UTC</div>\n"
            "<div class=\"section\"><h2>Details</h2><table>" + rows + "</table></div>\n"
            f"<div class=\"section\"><h2>Indicators</h2><ul>{indicators_html}</ul></div>\n"
            f"<div class=\"section\"><h2>Strings (preview)</h2><ul>{strings_html}</ul></div>\n"
            "</body>\n</html>\n"
        )
        html_path = REPO_ROOT / "analysis" / f"report_{safe_name}_{now}.html"
        html_path.write_text(html_content, encoding="utf-8")

        if out_format == "pdf":
            # Try to generate PDF using wkhtmltopdf if available; otherwise fall back to HTML
            pdf_path = REPO_ROOT / "analysis" / f"report_{safe_name}_{now}.pdf"
            wkhtml = shutil.which("wkhtmltopdf")
            note = ""
            if wkhtml:
                try:
                    result = subprocess.run([wkhtml, str(html_path), str(pdf_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
                    if result.returncode == 0 and pdf_path.exists():
                        return jsonify({
                            "saved": True,
                            "format": "pdf",
                            "path": str(pdf_path.relative_to(REPO_ROOT)),
                            "download": f"/analysis/{pdf_path.name}"
                        })
                    else:
                        note = (result.stderr or "wkhtmltopdf failed").strip()
                except Exception as ex:
                    note = f"wkhtmltopdf error: {ex}"
            # Fallback to HTML link with note
            return jsonify({
                "saved": True,
                "format": "html",
                "note": (note or "PDF not available; open HTML and use Print to PDF in your browser."),
                "path": str(html_path.relative_to(REPO_ROOT)),
                "download": f"/analysis/{html_path.name}"
            })

        # HTML success
        return jsonify({
            "saved": True,
            "format": "html",
            "path": str(html_path.relative_to(REPO_ROOT)),
            "download": f"/analysis/{html_path.name}"
        })

    # Default: Markdown
    report_path = REPO_ROOT / "analysis" / f"report_{safe_name}_{now}.md"
    report_lines = [
        f"# Analysis Report: {sample}",
        "",
        f"- Kind: {analysis_kind}",
        f"- File Type: {ftype}",
        f"- Size: {path.stat().st_size if path.exists() else 0} bytes",
        f"- Entropy: {ent}",
        f"- Hashes: MD5={hashes.get('md5','')}, SHA1={hashes.get('sha1','')}, SHA256={hashes.get('sha256','')}",
        "",
        "## Indicators",
        f"- URLs: {', '.join(findings.get('urls', [])) or 'None'}",
        f"- IPs: {', '.join(findings.get('ips', [])) or 'None'}",
        f"- Emails: {', '.join(findings.get('emails', [])) or 'None'}",
        "",
        "## Strings (preview)",
        "",
        "\n".join([f"- {s}" for s in strings]) or "(no printable strings)",
    ]
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    return jsonify({"saved": True, "format": "md", "path": str(report_path.relative_to(REPO_ROOT)), "download": f"/analysis/{report_path.name}"})


@app.get("/api/reports")
def api_reports():
    out: List[Dict[str, str]] = []
    analysis_dir = (REPO_ROOT / "analysis")
    if analysis_dir.exists():
        for pattern in ("report_*.md", "report_*.html", "report_*.pdf"):
            for p in analysis_dir.glob(pattern):
                out.append({"name": p.name, "path": f"analysis/{p.name}"})
    out.sort(key=lambda x: x["name"], reverse=True)
    return jsonify({"reports": out})


@app.get("/api/artifacts")
def api_artifacts():
    files = []
    for rel in list_artifacts().get("compiled", []):
        files.append(SAMPLES_DIR / rel)
    for rel in list_artifacts().get("sandbox_output", []):
        files.append(SAMPLES_DIR / rel)
    mem_file = io.BytesIO()
    with zipfile.ZipFile(mem_file, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            arcname = f.relative_to(SAMPLES_DIR)
            zf.write(f, arcname=str(arcname))
    mem_file.seek(0)
    return send_file(mem_file, mimetype="application/zip", as_attachment=True, download_name="artifacts.zip")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


