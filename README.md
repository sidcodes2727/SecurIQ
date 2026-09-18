# 🛡️ AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

A comprehensive security assessment framework that analyzes IPsec VPN traffic from PCAP files, classifies encrypted traffic types using machine learning, and provides transparent security assessments with an interactive cybersecurity dashboard.

## ✨ Key Features

### Protocol Analysis
- **IKE Parsing**: Full IKEv1/IKEv2 header and payload parsing including SA proposals, transforms, and notifies
- **ESP/AH Detection**: SPI extraction, sequence number analysis, payload size statistics
- **Algorithm Identification**: Encryption, integrity, PRF, and DH group detection from IKE negotiation
- **Mode Detection**: Tunnel vs Transport mode from USE_TRANSPORT_MODE notify
- **NAT-T Detection**: NAT Traversal via UDP port 4500 and NAT detection payloads
- **PFS Detection**: Perfect Forward Secrecy from CREATE_CHILD_SA Key Exchange payloads
- **Honest Reporting**: Unobservable fields marked as "Not Observable" instead of guessing

### ML Traffic Classification
- **7 Traffic Types**: ICMP, Web, VoIP, Video, Email, Chat, File Transfer
- **30 Features**: Packet sizes, timing, burst patterns, direction ratios, entropy
- **RandomForest**: 200 estimators with cross-validation
- **Explainability**: Feature importance rankings and confidence scores
- **Synthetic Dataset**: Realistic flow feature generation based on traffic profiles

### Security Assessment
- **7 Scoring Categories**: Cryptographic strength, key exchange, integrity, SA parameters, replay protection, configuration, metadata exposure
- **Transparent Rules**: Every score has documented rationale
- **Severity Levels**: Critical, High, Medium, Low, Informational
- **Threat Matrix**: MITRE ATT&CK-style threat mapping with likelihood/impact scores
- **Recommendations**: Prioritized, actionable security improvements

### Dashboard
- **Dark Cybersecurity Theme**: Professional, modern dark UI with cyan/green accents
- **PCAP Upload**: Drag-and-drop with file validation
- **Live Capture**: Interface for tcpdump-based captures (requires privileges)
- **VPN Analysis**: Protocol details, SA information, packet timeline
- **Classification**: Traffic type predictions with confidence and feature importance
- **Security Assessment**: Risk gauge, category scores, findings, threat matrix
- **Reports**: Executive summary and technical report generation
- **Dataset/Model Info**: Training metrics, confusion matrix, feature importance

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│            React/TypeScript Frontend (Vite)          │
│  Dark cybersecurity dashboard with 8 sections        │
└────────────────────┬────────────────────────────────┘
                     │ REST API (localhost:8000)
┌────────────────────┴────────────────────────────────┐
│              Python/FastAPI Backend                   │
│                                                      │
│  ├── analyzers/                                      │
│  │   ├── pcap_parser.py      # Scapy PCAP parsing   │
│  │   ├── ipsec_analyzer.py   # IPsec deep analysis  │
│  │   └── flow_extractor.py   # ML feature extraction│
│  │                                                   │
│  ├── ml/                                             │
│  │   ├── model.py            # RandomForest classifier│
│  │   └── synthetic_data.py   # Dataset generation    │
│  │                                                   │
│  ├── security/                                       │
│  │   ├── scoring_engine.py   # Rule-based scoring    │
│  │   └── threat_matrix.py    # Threat mapping        │
│  │                                                   │
│  ├── reports/                                        │
│  │   └── generator.py        # Report generation     │
│  │                                                   │
│  └── sample_data/                                    │
│      └── generate_sample_pcap.py  # Test PCAPs       │
└─────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- npm

### Setup

```bash
# Clone and enter the project
cd SIH

# Option 1: Run the setup script
chmod +x setup.sh
./setup.sh

# Option 2: Manual setup
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### Run

**Terminal 1 - Backend (from project root):**
```bash
source backend/venv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

The backend automatically:
1. Generates 5 sample PCAP files (different VPN scenarios)
2. Generates a synthetic dataset (3,500 samples across 7 traffic classes)
3. Trains the ML model on startup

### Run Tests

```bash
cd backend
python3 -m pytest tests/ -v
```

## 📊 Sample PCAP Scenarios

| Scenario | IKE Version | Encryption | DH Group | Notes |
|----------|-------------|------------|----------|-------|
| `ikev2_aes256gcm` | IKEv2 | AES-256-GCM | ECP-384 | Strong config with PFS |
| `ikev2_aes128cbc` | IKEv2 | AES-128-CBC | MODP-2048 | Moderate config |
| `ikev1_3des` | IKEv1 | 3DES-CBC* | — | Weak/legacy config |
| `natt_tunnel` | IKEv2 | — | — | NAT-T encapsulated |
| `mixed_traffic` | IKEv2 | AES-256-GCM | ECP-384 | Multiple traffic patterns |

\* *Algorithm determined from IKE negotiation context, not ESP ciphertext*

## 🔒 Security Scoring Categories

| Category | Weight | Description |
|----------|--------|-------------|
| Cryptographic Strength | 25% | Encryption algorithm and key length |
| Key Exchange | 20% | DH group strength and PFS |
| Authentication/Integrity | 15% | HMAC/AEAD algorithm strength |
| SA Parameters | 10% | SA count, rekeying, lifetime |
| Replay Protection | 10% | Sequence number consistency |
| Configuration | 10% | IKE version, mode, protocol choices |
| Metadata Exposure | 10% | Transport mode, NAT-T, IP visibility |

## 🤖 ML Traffic Classification

### Features Used (30 total)
- **Size stats**: mean, std, min, max, median, Q1, Q3, IQR
- **Timing stats**: IAT mean, std, min, max, median, coefficient of variation
- **Rate stats**: packet rate, byte rate, bits per second
- **Direction**: forward/backward ratios and counts
- **Burst analysis**: burst count, average burst size, burst rate
- **Entropy**: size entropy, IAT regularity

### Traffic Profiles
| Type | Characteristics |
|------|----------------|
| ICMP | Small (98-130B), regular timing, symmetric |
| Web | Variable (300-800B), bursty, asymmetric |
| VoIP | Small fixed (160-220B), very regular (~20ms IAT) |
| Video | Large (900-1400B), sustained, slightly variable |
| Email | Medium (200-600B), sparse, bursty transfers |
| Chat | Very small (80-200B), irregular timing |
| File Transfer | Large (1200-1500B), sustained throughput |

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload PCAP file |
| GET | `/api/upload/list` | List uploads and samples |
| POST | `/api/analyze/{file_id}` | Run full analysis |
| GET | `/api/analysis/{id}` | Get analysis results |
| GET | `/api/security/{id}` | Security assessment |
| GET | `/api/security/{id}/findings` | Security findings |
| GET | `/api/security/{id}/threat-matrix` | Threat matrix |
| GET | `/api/ml/classify/{id}` | Traffic classification |
| GET | `/api/ml/model-info` | Model information |
| POST | `/api/ml/train` | Retrain model |
| GET | `/api/reports/{id}/executive` | Executive report |
| GET | `/api/reports/{id}/technical` | Technical report |
| POST | `/api/dataset/generate` | Generate dataset |
| POST | `/api/capture/start` | Start live capture |

## 🧪 Technology Stack

- **Backend**: Python 3.9+, FastAPI, Scapy, scikit-learn, NumPy, Pandas
- **Frontend**: React 18, TypeScript, Vite, React Router
- **ML**: RandomForest (scikit-learn), joblib for persistence
- **Packet Analysis**: Scapy for PCAP parsing and IKE/ESP protocol dissection
- **Styling**: Pure CSS with custom properties (dark cybersecurity theme)

## 📝 Design Philosophy

1. **Honest Analysis**: Observable fields are parsed from actual packet data. Unobservable fields (e.g., encryption algorithm from ESP ciphertext) are marked "Not Observable."
2. **Transparent Scoring**: Every security score has documented rules with clear rationale.
3. **ML Explainability**: Feature importance is surfaced alongside predictions. Confidence scores indicate model certainty.
4. **Modular Architecture**: Each component is independent and testable.
5. **Demo-Ready**: Auto-generates samples and trains the model on startup for immediate demonstration.
