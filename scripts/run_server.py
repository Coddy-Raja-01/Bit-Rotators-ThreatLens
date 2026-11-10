import os
import sys
from pathlib import Path

# Add project root to path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.config import load_env  # noqa: E402

load_env()

import uvicorn  # noqa: E402
from backend.database import init_db  # noqa: E402
from backend.ml.train import train  # noqa: E402

if __name__ == "__main__":
    print("=" * 60)
    print(" ThreatLens - Phishing & Malicious Website Detection Platform")
    print("=" * 60)

    # 1. Initialize SQLite Database
    print("[1/3] Initializing SQLite database...")
    init_db()

    # 2. Check ML model
    model_path = root_dir / "backend" / "ml" / "model.joblib"
    if not model_path.exists():
        print("[2/3] Training initial Random Forest phishing model...")
        train()
    else:
        print("[2/3] Machine Learning model ready.")

    # 3. Start Uvicorn Server
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "127.0.0.1")

    print(f"[3/3] Starting ThreatLens server on http://{host}:{port}")
    print(f"      - Web UI: http://{host}:{port}/")
    print(f"      - API Docs: http://{host}:{port}/docs")
    print("=" * 60)

    uvicorn.run("backend.main:app", host=host, port=port, reload=False, log_level="info")
