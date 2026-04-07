
import io, re, tokenize, pathlib

BASE = pathlib.Path(r"E:\Fake Malware\.claude\worktrees\optimistic-hypatia")

PYTHON_FILES = [
    "app.py",
    "attack_runner.py",
    "malware_lab_bp.py",
    "report_generator.py",
    "train_models.py",
    "loaders/__init__.py",
    "loaders/ember_loader.py",
    "loaders/feature_constraints.py",
    "loaders/hf_targets.py",
    "loaders/nslkdd_loader.py",
    "loaders/phishing_loader.py",
    "loaders/virustotal_checker.py",
    "tests/test_attack_runner.py",
    "sink/sink_server.py",
]
JS_FILES = ["static/dashboard.js", "static/malware_main.js"]
HTML_FILES = ["templates/dashboard.html", "templates/landing.html", "templates/malware_lab.html", "templates/report.html"]
