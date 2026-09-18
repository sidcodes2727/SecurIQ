"""
Configuration constants for the IPsec VPN Analyzer.
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = DATA_DIR / "models"
DATASET_DIR = DATA_DIR / "datasets"
SAMPLE_DIR = DATA_DIR / "samples"
CAPTURE_DIR = DATA_DIR / "captures"

# Ensure directories exist
for d in [DATA_DIR, UPLOAD_DIR, MODEL_DIR, DATASET_DIR, SAMPLE_DIR, CAPTURE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Upload settings
MAX_UPLOAD_SIZE_MB = 100
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# ML settings
ML_MODEL_PATH = MODEL_DIR / "traffic_classifier.joblib"
ML_SCALER_PATH = MODEL_DIR / "feature_scaler.joblib"
TRAFFIC_CLASSES = ["icmp", "web", "voip", "video", "email", "chat", "file_transfer"]
SYNTHETIC_SAMPLES_PER_CLASS = 500
TEST_SPLIT_RATIO = 0.2

# Security scoring weights
SCORING_WEIGHTS = {
    "cryptographic_strength": 0.25,
    "key_exchange": 0.20,
    "authentication_integrity": 0.15,
    "sa_parameters": 0.10,
    "replay_protection": 0.10,
    "configuration": 0.10,
    "metadata_exposure": 0.10,
}

# Severity levels
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

# IKE/IPsec constants
IKE_PORT = 500
IKE_NATT_PORT = 4500
ESP_PROTOCOL = 50
AH_PROTOCOL = 51

# Algorithm strength ratings (0-100)
ENCRYPTION_SCORES = {
    "AES-256-GCM": 100,
    "AES-GCM-256": 100,
    "AES-256-CBC": 85,
    "AES-CBC-256": 85,
    "AES-192-GCM": 95,
    "AES-GCM-192": 95,
    "AES-192-CBC": 80,
    "AES-CBC-192": 80,
    "AES-128-GCM": 90,
    "AES-GCM-128": 90,
    "AES-128-CBC": 70,
    "AES-CBC-128": 70,
    "3DES-CBC": 30,
    "DES-CBC": 5,
    "NULL": 0,
    "Unknown": 50,
}

INTEGRITY_SCORES = {
    "HMAC-SHA2-512": 100,
    "HMAC-SHA2-384": 95,
    "HMAC-SHA2-256": 90,
    "HMAC-SHA2-256-128": 90,
    "HMAC-SHA1-96": 60,
    "HMAC-SHA1": 60,
    "HMAC-MD5-96": 25,
    "HMAC-MD5": 25,
    "AES-XCBC-96": 75,
    "AES-CMAC-96": 75,
    "NONE (AEAD)": 100,  # AEAD handles integrity
    "NULL": 0,
    "Unknown": 50,
}

DH_GROUP_SCORES = {
    1: 10,    # 768-bit MODP
    2: 20,    # 1024-bit MODP
    5: 40,    # 1536-bit MODP
    14: 70,   # 2048-bit MODP
    15: 75,   # 3072-bit MODP
    16: 80,   # 4096-bit MODP
    17: 85,   # 6144-bit MODP
    18: 90,   # 8192-bit MODP
    19: 85,   # 256-bit ECP
    20: 90,   # 384-bit ECP
    21: 95,   # 521-bit ECP
    31: 95,   # Curve25519
    32: 95,   # Curve448
}

# Live capture settings
DEFAULT_CAPTURE_INTERFACE = "any"
DEFAULT_CAPTURE_FILTER = "esp or udp port 500 or udp port 4500 or proto 51"
MAX_CAPTURE_DURATION = 300  # seconds
MAX_CAPTURE_PACKETS = 10000
