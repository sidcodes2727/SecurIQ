"""
Configuration constants for the IPsec VPN Analyzer.
"""
import os
from pathlib import Path

from backend.testbed.traffic_models import TRAFFIC_CLASSES, TRAFFIC_LABELS

# Base paths (SECURIQ_DATA_DIR relocates all generated data, e.g. for tests)
BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.environ.get("SECURIQ_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = DATA_DIR / "models"
DATASET_DIR = DATA_DIR / "datasets"
SAMPLE_DIR = DATA_DIR / "samples"
CAPTURE_DIR = DATA_DIR / "captures"
ANALYSIS_DIR = DATA_DIR / "analyses"
EVALUATION_DIR = DATA_DIR / "evaluation"

for d in [DATA_DIR, UPLOAD_DIR, MODEL_DIR, DATASET_DIR, SAMPLE_DIR, CAPTURE_DIR, ANALYSIS_DIR, EVALUATION_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Upload settings
MAX_UPLOAD_SIZE_MB = int(os.environ.get("SECURIQ_MAX_UPLOAD_MB", 100))
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
STORED_PACKETS_LIMIT = 5000   # packets kept per analysis for the packet view

# ML settings
ML_MODEL_PATH = MODEL_DIR / "traffic_classifier_v2.joblib"
TRAFFIC_CLASS_LABELS = TRAFFIC_LABELS
TRAINING_FLOWS_PER_CLASS = 60

# Security scoring weights (PS §d categories); must sum to 1.0
SCORING_WEIGHTS = {
    "cryptographic_strength": 0.20,
    "key_exchange": 0.15,
    "forward_secrecy": 0.10,
    "authentication_integrity": 0.10,
    "sa_lifetime": 0.10,
    "replay_protection": 0.10,
    "configuration_compliance": 0.15,
    "metadata_exposure": 0.10,
}

# Severity levels
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"
SEVERITY_ORDER = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]

# A single Critical/High finding caps the overall score (weakest-link principle)
SCORE_CAP_CRITICAL = 40
SCORE_CAP_HIGH = 70

# Live capture settings
DEFAULT_CAPTURE_FILTER = "esp or ah or udp port 500 or udp port 4500"
MAX_CAPTURE_DURATION = 120  # seconds
MAX_CAPTURE_PACKETS = 200_000
