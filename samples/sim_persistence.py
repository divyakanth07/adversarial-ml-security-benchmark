import os
from pathlib import Path

if __name__ == "__main__":
    # Simulate creating a persistence artifact inside sandbox_output
    out_dir = Path("sandbox_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "simulated_startup_entry.txt"
    p.write_text("SIM_PERSISTENCE: pretend registry or cron entry here", encoding="utf-8")
    print("SIM_PERSISTENCE: created", p)


