# Security Research Labs

> MCA Final Year Project · Divyakanth Kiri P (RA2332241010322)

A unified Dockerised Flask platform combining two security research tools: an **Adversarial ML Attack Toolkit** that benchmarks real security classifiers against state-of-the-art evasion attacks, and a **Safe Malware Analysis Lab** that runs synthetic malware samples through static, dynamic, and network analysis pipelines.

---

## Labs

### ART Lab — Adversarial ML Attack Toolkit

Trains three ML security classifiers then runs adversarial attacks from IBM's Adversarial Robustness Toolbox against them. Results are displayed on an interactive Plotly.js dashboard with heatmaps, accuracy charts, epsilon-sweep curves, and defence comparisons. Every completed benchmark run is saved as a shareable session.

### Malware Lab — Safe Malware Analysis Sandbox

Analyses eight synthetic (benign) malware simulator samples through static analysis, deep static analysis with AST and objdump, sandboxed dynamic execution, network capture, and YARA signature detection. Generates HTML, PDF, and Markdown analysis reports.

---

## Quick Start

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

```
ANTHROPIC_API_KEY=sk-ant-...
VIRUSTOTAL_API_KEY=...
HF_TOKEN=hf_...
```

```bash
docker compose up --build
```

Open `http://localhost:5000` — the landing page lets you choose which lab to enter.

> On first launch, Docker automatically trains all three ML models before starting the server. Subsequent starts reuse saved models instantly.

---

## Manual Setup (no Docker)

```bash
pip install -r requirements.txt

python train_models.py

python app.py
```

Run benchmarks from the CLI:

```bash
python attack_runner.py
python attack_runner.py --model ids --attack fgsm --eps 0.1
```

---

## URL Structure

| URL | Description |
|-----|-------------|
| `/` | Landing page — choose a lab |
| `/art` | ART Lab dashboard |
| `/art?session=<id>` | Load a specific saved session |
| `/malware` | Malware Analysis Lab |
| `/report` | AI-generated threat analysis report |

---

## ART Lab Features

| Feature | Detail |
|---------|--------|
| **5 Attack Methods** | FGSM, HopSkipJump, ZooAttack, C&W L2, DeepFool |
| **3 Security Classifiers** | Malware (RandomForest), IDS (GradientBoosting), Phishing (LogisticRegression) |
| **15 Attack–Model Pairs** | Full benchmark matrix with 4 metrics per pair |
| **Interactive Charts** | Evasion rate heatmap, accuracy bar chart, confidence delta line chart |
| **Epsilon Sweep** | Evasion rate vs epsilon curve per model |
| **Adversarial Defence** | Adversarial training with before/after comparison |
| **Threat Scenario Profiles** | Pre-configured attacker profiles (APT, ransomware, phishing campaign, etc.) |
| **Feature Constraints** | Realistic perturbation masks per domain |
| **Run History** | Trend chart of evasion rate across last 30 runs |
| **Session Management** | Every run auto-saves as a shareable 8-char session code |
| **VirusTotal Integration** | Scan any URL or SHA-256 hash against 70+ AV engines |
| **HuggingFace Models** | Classify URLs with production security BERT models + URL mutation evasion demo |
| **AI Threat Report** | Claude Haiku generates a dual-audience report with PoC Python scripts per attack |
| **Progress Polling** | Live progress bar with ETA during long benchmark runs |

---

## Malware Lab Features

| Feature | Detail |
|---------|--------|
| **Static Analysis** | File type, hashes (MD5/SHA1/SHA256), Shannon entropy, URLs/IPs/emails, strings preview |
| **Deep Static** | Python AST parsing, objdump headers/sections/imports, extended strings |
| **Dynamic Execution** | Sandboxed run in Docker worker with 10s timeout and 256 MB memory cap |
| **Network Simulation** | TCP sink server on 127.0.0.1:9009 captures simulated C2 traffic |
| **YARA Detection** | Runs `yara/sim_rules.yar` against all samples; falls back to string-match simulation |
| **File Upload** | Upload files for static analysis (not execution) |
| **Report Generation** | HTML, PDF (wkhtmltopdf), and Markdown analysis reports |
| **8 Synthetic Samples** | All benign simulators — packer, dropper, persistence, C2 mimic, obfuscation, ELF mimic |

---

## Session Management

Every benchmark run in the ART Lab is automatically saved as a named session.

- Click **＋ New Session** to generate a session ID immediately — the URL updates to `/art?session=<id>` before any benchmark runs, so you can share the link in advance
- Running a benchmark while a session is active updates that session in-place (same ID)
- Click the session code in the bar to copy it; click **⎘ Copy Link** to copy the full shareable URL
- Click **⏮ Last Session** to restore the most recent run
- Click **🔗 Open Session** to browse or enter any session code
- Opening `/art?session=<id>` in a browser loads that session automatically

---

## Models & Attacks

### Security Classifiers

| Model | Algorithm | Features | Dataset |
|-------|-----------|----------|---------|
| Malware | RandomForestClassifier | 2381 (EMBER PE) | Synthetic or `data/ember.csv` |
| IDS | GradientBoostingClassifier | 41 (NSL-KDD) | Synthetic or `data/nslkdd.csv` |
| Phishing | LogisticRegression | 30 (UCI Phishing) | Synthetic or `data/phishing.csv` |

All models reach ≥ 80% test accuracy before benchmarking proceeds.

### Attack Methods

| Attack | Type | ART Class | Notes |
|--------|------|-----------|-------|
| FGSM | White-box | `FastGradientMethod` | 500 samples, gradient-based |
| HopSkipJump | Black-box | `HopSkipJump` | 200 samples, decision-boundary |
| ZooAttack | Black-box | `ZooAttack` | 100 samples, query-efficient |
| C&W L2 | White-box | `CarliniL2Method` | L2-norm optimisation |
| DeepFool | White-box | `DeepFool` | Minimal perturbation |

---

## Metrics

| Metric | Definition |
|--------|-----------|
| `original_accuracy` | Model accuracy on clean test data |
| `post_attack_accuracy` | Model accuracy on adversarial examples |
| `evasion_rate` | Fraction of correctly-classified malicious samples flipped to benign |
| `confidence_delta` | Mean drop in predicted probability for the true class |
| `queries_used` | Total model queries consumed (black-box attacks) |

Risk classification: evasion_rate > 50% → **CRITICAL** · 20–50% → **HIGH** · < 20% → **MODERATE**

---

## Real-World Targets

### VirusTotal

Set `VIRUSTOTAL_API_KEY` in `.env`. In the **🌐 Real-World Targets** panel on the ART Lab dashboard:

- **Scan URL** — submits a URL for fresh scanning across 70+ AV engines; falls back to cached report if available
- **Lookup Hash** — looks up a SHA-256 file hash against the VirusTotal database

Free tier: 4 requests/minute, 500/day.

### HuggingFace Security Models

Set `HF_TOKEN` in `.env`. Two production security classifiers are available:

- `ealvaradob/bert-finetuned-phishing` — BERT fine-tuned for phishing URL detection
- `elftsdmr/malware-url-detect` — malware URL detector

The **⚡ Run Evasion Demo** applies 7 documented URL obfuscation techniques (@ trick, subdomain injection, path injection, partial URL encoding, hyphen split, TLD swap, original) and reports which mutations evade the selected model.

---

## API Reference

### ART Lab

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/art` | ART Lab dashboard |
| `GET` | `/api/results` | Return `benchmark_results.json` |
| `POST` | `/api/run-benchmark` | Run benchmark `{model, attack, epsilon, session_id?}` |
| `GET` | `/api/progress` | Live benchmark progress |
| `GET` | `/api/profiles` | Attack scenario profiles |
| `POST` | `/api/epsilon-sweep` | Evasion rate vs epsilon curve |
| `POST` | `/api/defend` | Apply adversarial training defence |
| `GET` | `/api/defense-results` | Return defence results |
| `GET` | `/api/history` | Last 30 run summaries |
| `GET` | `/api/constraints` | Feature constraint mask for a model |
| `GET` | `/api/generate-report` | Generate AI threat report via Claude |
| `GET` | `/report` | Rendered AI report page |
| `POST` | `/api/sessions/new` | Create empty session, return `{session_id}` |
| `GET` | `/api/sessions` | List all sessions (metadata) |
| `GET` | `/api/sessions/<id>` | Load full results for a session |
| `POST` | `/api/virustotal-scan` | Scan URL or hash on VirusTotal |
| `GET` | `/api/hf-models` | List HuggingFace security models |
| `POST` | `/api/hf-classify` | Classify a URL with a HF model |
| `POST` | `/api/hf-evasion` | Run URL mutation evasion demo |

### Malware Lab

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/malware` | Malware Lab dashboard |
| `GET` | `/malware/api/samples` | List samples, artifacts, sandbox output |
| `POST` | `/malware/api/compile` | Compile a C sample with GCC |
| `POST` | `/malware/api/run` | Execute a whitelisted sample |
| `GET` | `/malware/api/static` | Quick static analysis of a sample |
| `GET` | `/malware/api/deep_static` | Deep analysis with AST + objdump |
| `GET` | `/malware/api/logs` | Return captured network messages |
| `POST` | `/malware/api/sink/start` | Start the TCP sink server |
| `POST` | `/malware/api/yara` | Run YARA rules against samples |
| `POST` | `/malware/api/upload` | Upload a file for analysis |
| `POST` | `/malware/api/report` | Generate HTML/PDF/MD analysis report |
| `GET` | `/malware/api/reports` | List generated reports |
| `GET` | `/malware/api/artifacts` | Download artifacts.zip |

---

## Project Structure

```
.
├── app.py                      # Flask app, landing page, ART Lab routes
├── malware_lab_bp.py           # Flask Blueprint — all Malware Lab routes
├── attack_runner.py            # ART attack execution + metrics
├── train_models.py             # Train and serialise all three classifiers
├── report_generator.py         # Claude Haiku AI report generation
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── loaders/
│   ├── ember_loader.py         # EMBER-style PE malware features (2381)
│   ├── nslkdd_loader.py        # NSL-KDD network intrusion features (41)
│   ├── phishing_loader.py      # UCI Phishing website features (30)
│   ├── feature_constraints.py  # Domain-realistic perturbation masks
│   ├── virustotal_checker.py   # VirusTotal API v3 client
│   └── hf_targets.py           # HuggingFace Inference Router client
│
├── templates/
│   ├── landing.html            # Mode selector (ART Lab / Malware Lab)
│   ├── dashboard.html          # ART Lab — Plotly.js dark dashboard
│   ├── malware_lab.html        # Malware Lab — dark themed UI
│   └── report.html             # AI threat report page with PoC code
│
├── static/
│   ├── dashboard.js            # ART Lab — charts, session mgmt, API calls
│   └── malware_main.js         # Malware Lab — tab navigation, API calls
│
├── models/                     # Trained .pkl models + numpy test splits
├── results/                    # benchmark_results.json, sessions/, history
│
├── samples/                    # Synthetic malware simulator samples
│   ├── sim_print.py
│   ├── sim_c2_mimic.py
│   ├── sim_netclient.py
│   ├── sim_packer.py
│   ├── sim_obfuscated.py
│   ├── sim_persistence.py
│   ├── sim_dropper.c
│   ├── sim_elf_mimic.c
│   ├── compiled/               # GCC output
│   ├── sandbox_output/         # Dynamic run artefacts
│   └── uploads/                # User-uploaded files (analysis only)
│
├── sink/
│   └── sink_server.py          # TCP listener on 127.0.0.1:9009
├── yara/
│   └── sim_rules.yar           # YARA signature rules
├── analysis/                   # Generated HTML/PDF/MD reports
├── logs/                       # Run history and sink capture logs
└── tests/
    └── test_attack_runner.py   # pytest suite
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Using Real Datasets

Place CSV files (all columns are features except the last, which is the 0/1 label) at:

| Path | Dataset |
|------|---------|
| `data/ember.csv` | EMBER PE malware features |
| `data/nslkdd.csv` | NSL-KDD network intrusion |
| `data/phishing.csv` | UCI Phishing websites |

---

## Ethics & Scope

All attacks target locally trained classifiers on synthetic or publicly available datasets. The Malware Lab samples are entirely benign simulators — they produce artefacts and output that mimic real malware behaviour without executing any harmful code. No real malware, real network traffic, or real phishing infrastructure is used anywhere in this project.

Built for academic and educational purposes only.

---

## Author

Divyakanth Kiri P · RA2332241010322 · MCA 2nd Year · Final Year Project
