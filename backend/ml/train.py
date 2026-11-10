import csv
from pathlib import Path
import hashlib
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from backend.ml.features import extract_features, FEATURE_COLUMNS

def train(data_path: str = None, model_output_path: str = None):
    """Train Random Forest model on sample URL dataset."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    
    if data_path is None:
        data_path = base_dir / "data" / "sample_urls.csv"
    else:
        data_path = Path(data_path)
        
    if model_output_path is None:
        model_output_path = base_dir / "backend" / "ml" / "model.joblib"
    else:
        model_output_path = Path(model_output_path)
        
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found at {data_path}")
        
    X = []
    y = []
    
    with open(data_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = row["url"].strip()
            label = int(row["label"].strip())
            feat = extract_features(raw_url)
            row_features = [feat[col] for col in FEATURE_COLUMNS]
            X.append(row_features)
            y.append(label)
            
    print(f"Loaded {len(X)} samples for training.")
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X, y)
    
    predictions = clf.predict(X)
    acc = accuracy_score(y, predictions)
    print(f"Training accuracy: {acc * 100:.2f}%")
    
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": clf,
        "feature_columns": FEATURE_COLUMNS,
        "accuracy": acc
    }
    joblib.dump(artifact, model_output_path)
    digest = hashlib.sha256(model_output_path.read_bytes()).hexdigest()
    checksum_path = model_output_path.with_suffix(model_output_path.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {model_output_path.name}\n", encoding="ascii")
        
    print(f"Model saved successfully to {model_output_path}")
    print(f"SHA-256 checksum saved to {checksum_path}")
    return clf

if __name__ == "__main__":
    train()
