# Adversarial ML Attack Toolkit — Security Model Benchmarking

> MCA Final Year Project · Divyakanth Kiri P (RA2332241010322)

A Dockerised Flask web platform that trains three ML security classifiers, runs adversarial attacks using IBM's Adversarial Robustness Toolbox (ART), visualises results on an interactive dashboard, and generates AI-powered threat reports via the Claude API.

---

## Features

| Feature | Detail |
|---------|--------|
| **3 Security Classifiers** | Malware (RandomForest), IDS (GradientBoosting), Phishing (LogisticRegression) |
| **3 Attack Methods** | FGSM (white-box), HopSkipJump (black-box), ZooAttack (black-box) |
| **9 Attack–Model Pairs** | Full benchmark matrix with 4 metrics per pair |
| **Interactive Dashboard** | Plotly.js heatmap, bar chart, line chart |
| **AI Threat Report** | Claude Haiku generates a structured 4-section security analysis |
| **Docker Compose** | One-command launch |
| **pytest Suite** | 6 unit tests covering loaders, metrics, attacks, and report generation |

---

## Stack

- **Python 3.10**
- **scikit-learn 1.3.2** — model training
- **adversarial-robustness-toolbox 1.20.0** — attack implementations
- **Flask 3.0.3** — web dashboard
- **Plotly.js** — browser-side charts
- **Anthropic Python SDK** — Claude Haiku AI reports
- **Docker + Docker Compose** — containerised deployment
- **pytest** — unit tests

---

## Quick Start (Docker — recommended)

```bash
# 1. Clone / open this folder
cd adversarial-ml-toolkit

# 2. Set your Anthropic API key (for AI reports — optional)
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-...

# 3. Build and launch (models are trained automatically on first run)
docker compose up --build

# 4. Open the dashboard
#    http://localhost:5000
```

> **Note:** The first launch trains three ML models. Subsequent starts reuse saved models instantly.

---

## Manual Setup (without Docker)

```bash
# Python 3.10 required
pip install -r requirements.txt

# Train models (run once; saves to models/)
python train_models.py

# Start the dashboard
python app.py
# → http://localhost:5000

# Run all 9 benchmarks from the CLI
python attack_runner.py

# Run specific benchmark
python attack_runner.py --model ids --attack fgsm --eps 0.1

# Generate AI report (requires ANTHROPIC_API_KEY in environment)
python report_generator.py
```

---

## Project Structure

```
.
├── app.py                  # Flask app (3 endpoints)
├── train_models.py         # Train & serialise all 3 classifiers
├── attack_runner.py        # ART attack execution + 4-metric scoring
├── report_generator.py     # Claude Haiku AI report generation
├── loaders/
│   ├── ember_loader.py     # EMBER-style PE malware features (2381)
│   ├── nslkdd_loader.py    # NSL-KDD network intrusion features (41)
│   └── phishing_loader.py  # UCI Phishing website features (30)
├── templates/
│   └── dashboard.html      # Plotly.js dashboard (dark theme)
├── static/
│   └── dashboard.js        # Chart rendering + API calls
├── models/                 # joblib .pkl files + numpy test splits
├── results/                # benchmark_results.json
├── data/                   # Optional real datasets
├── tests/
│   └── test_attack_runner.py   # 6 pytest unit tests
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Dashboard HTML |
| `GET`  | `/api/results` | Return `benchmark_results.json` |
| `POST` | `/api/run-benchmark` | Run benchmark: `{model, attack, epsilon}` |
| `GET`  | `/api/generate-report` | Generate AI threat report |

### Example — run FGSM on IDS model

```bash
curl -X POST http://localhost:5000/api/run-benchmark \
  -H "Content-Type: application/json" \
  -d '{"model": "ids", "attack": "fgsm", "epsilon": 0.05}'
```

---

## Models & Attacks

### Security Classifiers

| Model | Algorithm | Features | Data |
|-------|-----------|----------|------|
| Malware | RandomForestClassifier | 2381 (EMBER PE) | Synthetic or `data/ember.csv` |
| IDS | GradientBoostingClassifier | 41 (NSL-KDD) | Synthetic or `data/nslkdd.csv` |
| Phishing | LogisticRegression | 30 (UCI Phishing) | Synthetic or `data/phishing.csv` |

All models reach ≥ 80% test accuracy before benchmarking proceeds.

### Attack Methods (IBM ART)

| Attack | Type | ART Class | Key Params |
|--------|------|-----------|-----------|
| FGSM | White-box | `FastGradientMethod` | eps=0.05 |
| HopSkipJump | Black-box | `HopSkipJump` | max_iter=50 |
| ZooAttack | Black-box | `ZooAttack` | max_iter=20 |

---

## Metrics (4 per attack–model pair)

| Metric | Definition |
|--------|-----------|
| `original_accuracy` | Model accuracy on clean test data |
| `post_attack_accuracy` | Model accuracy on adversarial examples |
| `evasion_rate` | Fraction of correctly-classified malicious samples flipped to benign |
| `confidence_delta` | Mean drop in predicted probability for the true class |

**Risk classification:** evasion_rate > 50% → CRITICAL | 20–50% → HIGH | < 20% → MODERATE

---

## Running Tests

```bash
pytest tests/ -v
```

Tests that require ART are automatically skipped when the package is unavailable.

---

## Using Real Datasets

Place CSV files (features in all columns except the last; label column is 0/1) at:

| Path | Dataset |
|------|---------|
| `data/ember.csv` | EMBER PE features |
| `data/nslkdd.csv` | NSL-KDD network traffic |
| `data/phishing.csv` | UCI Phishing websites |

---

## Ethics & Scope

Built for academic and educational purposes only.
All attacks run against locally trained classifiers on synthetic or publicly available datasets.
No real malware, real network traffic, or real phishing infrastructure is used.

---

## Author

Divyakanth Kiri P (RA2332241010322) — MCA 2nd Year, Final Year Project
