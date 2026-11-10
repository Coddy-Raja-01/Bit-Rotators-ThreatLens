import sys
from pathlib import Path

# Add project root to path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.ml.train import train

if __name__ == "__main__":
    print("Starting ThreatLens ML model training...")
    train()
    print("Training complete.")
