# ⚛ QuantumShield — PQC Scanner
### PNB Cybersecurity Hackathon 2025-26 | Theme: Quantum-Proof Systems

> **"Quantum-Ready Cybersecurity for Future-Safe Banking"**

---

## 🎯 Problem Statement
Develop a software scanner to validate deployment of Quantum-proof ciphers and create a Cryptographic Bill of Materials (CBOM) inventory for public-facing applications.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    QuantumShield                         │
├──────────────────┬──────────────────────────────────────┤
│   React Frontend │         FastAPI Backend               │
│   (Port 3000)    │         (Port 8000)                   │
│                  │                                       │
│  • Dashboard     │  • TLS Deep Inspector                 │
│  • CBOM Viewer   │  • Certificate Parser                 │
│  • PQC Scoring   │  • CBOM Generator (CycloneDX v1.4)   │
│  • Batch Scanner │  • PQC Assessment Engine             │
│  • Report Export │  • REST API                          │
└──────────────────┴──────────────────────────────────────┘
```

## ✨ Key Features

### 🔍 Scanner Capabilities
- **TLS Inspection**: Full handshake analysis — cipher suites, protocol versions, key exchange
- **Certificate Analysis**: X.509 certificate parsing, key type/size, SANs, validity, CA chain
- **HTTP Security Headers**: HSTS, CSP, X-Frame-Options analysis
- **Batch Scanning**: Up to 20 public-facing assets simultaneously

### 📜 CBOM (Cryptographic Bill of Materials)
- CycloneDX v1.4 compliant CBOM generation
- Per-asset cryptographic component inventory
- JSON export for integration with GRC tools
- NIST SP 800-235 aligned

### 🏆 PQC Assessment & Certification
- **PQC Score (0–100)** based on NIST FIPS 203/204/205 compliance
- **Quantum-Safe Labels**: Automatically issues "Fully Quantum Safe" / "PQC Ready" / "Vulnerable" badges
- Actionable remediation roadmap for each asset

### ⚛ NIST PQC Standards Supported
| Standard | Algorithm | Type | Security Level |
|----------|-----------|------|---------------|
| FIPS 203 | ML-KEM-768 | Key Encapsulation | Level 3 (★ Recommended) |
| FIPS 204 | ML-DSA-65 | Digital Signature | Level 3 (★ Recommended) |
| FIPS 205 | SLH-DSA-SHA2-192s | Hash Signature | Level 3 |

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
git clone <repo>
cd quantumshield
docker compose up -d
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000/docs
```

### Option 2: Local Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan/quick` | Quick single-target TLS scan |
| POST | `/api/v1/scan/batch` | Start async batch scan job |
| GET | `/api/v1/scan/job/{id}` | Get scan job results |
| GET | `/api/v1/scan/jobs` | List all scan jobs |
| POST | `/api/v1/reports/cbom` | Generate CBOM report |
| GET | `/api/v1/reports/badge/{target}` | Get PQC badge for asset |
| GET | `/api/v1/algorithms/pqc` | NIST PQC algorithm reference |

## 🔐 PQC Scoring Methodology

| Score | Status | Meaning |
|-------|--------|---------|
| 85–100 | 🟢 QUANTUM SAFE | NIST PQC algorithms deployed |
| 65–84 | 🟡 PQC READY | Hybrid PQC, strong classical |
| 40–64 | 🟠 TRANSITIONING | Partial migration needed |
| 0–39 | 🔴 VULNERABLE | Immediate action required |

## 🛡️ Addressing HNDL (Harvest Now, Decrypt Later)
The scanner specifically identifies:
- RSA/ECDSA certificates vulnerable to Shor's algorithm
- ECDHE/DHE key exchanges that leak to quantum adversaries
- Legacy ciphers (3DES, RC4) that are classically AND quantumly broken
- TLS versions (1.0, 1.1) with known vulnerabilities

## 📋 Team
PNB Cybersecurity Hackathon 2025-26 Submission
