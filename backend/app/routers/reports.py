from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone

router = APIRouter()

class ReportRequest(BaseModel):
    job_id: Optional[str] = None
    scan_results: Optional[List[dict]] = None
    report_title: str = "QuantumShield PQC Assessment Report"
    organization: str = "Organization"

@router.post("/reports/cbom")
async def generate_cbom_report(request: ReportRequest):
    """Generate a consolidated CBOM (Cryptographic Bill of Materials) report."""
    from app.routers.scanner import scan_jobs

    results = []
    if request.job_id:
        if request.job_id not in scan_jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        results = scan_jobs[request.job_id].get("results", [])
    elif request.scan_results:
        results = request.scan_results
    else:
        raise HTTPException(status_code=400, detail="Provide job_id or scan_results")

    # Build consolidated CBOM
    all_components = []
    summary = {
        "total_assets": len(results),
        "quantum_safe": 0,
        "pqc_ready": 0,
        "vulnerable": 0,
        "critical_issues": []
    }

    for result in results:
        target = result.get("target", "Unknown")
        pqc = result.get("pqc_assessment", {})
        cbom = result.get("cbom", {})
        tls = result.get("tls_info", {})

        status = pqc.get("status", "UNKNOWN")
        if status == "QUANTUM_SAFE":
            summary["quantum_safe"] += 1
        elif status == "PQC_READY":
            summary["pqc_ready"] += 1
        else:
            summary["vulnerable"] += 1

        # Collect critical issues
        for issue in pqc.get("issues", []):
            if issue.get("severity") in ["CRITICAL", "HIGH"]:
                summary["critical_issues"].append({
                    "target": target,
                    "issue": issue["issue"],
                    "action": issue["action"]
                })

        asset_entry = {
            "asset": target,
            "port": result.get("port", 443),
            "scan_timestamp": result.get("timestamp"),
            "tls_version": tls.get("tls_version", "N/A"),
            "cipher_suite": tls.get("cipher_suite", "N/A"),
            "key_exchange": tls.get("key_exchange", "N/A"),
            "cert_key_type": tls.get("cert_key_type", "N/A"),
            "cert_key_bits": tls.get("cert_key_bits", 0),
            "pqc_score": pqc.get("score", 0),
            "pqc_status": status,
            "pqc_label": pqc.get("label", "N/A"),
            "issues": pqc.get("issues", []),
            "components": cbom.get("components", [])
        }
        all_components.append(asset_entry)

    report = {
        "report_metadata": {
            "title": request.report_title,
            "organization": request.organization,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "cbom_version": "1.4",
            "scanner": "QuantumShield v1.0",
            "nist_reference": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"]
        },
        "executive_summary": summary,
        "assets": all_components,
        "recommendations": {
            "immediate": [
                "Disable TLS 1.0 and TLS 1.1 on all public-facing assets",
                "Replace RC4, 3DES, and DES ciphers with AES-256-GCM",
                "Enforce TLS 1.3 as minimum version"
            ],
            "short_term": [
                "Begin PKI migration planning for ML-DSA (FIPS 204) certificates",
                "Evaluate hybrid key exchange (X25519+ML-KEM) for TLS connections",
                "Implement crypto-agility framework for rapid algorithm updates"
            ],
            "long_term": [
                "Full migration to NIST PQC standardized algorithms (ML-KEM, ML-DSA, SLH-DSA)",
                "Establish Cryptographic Bill of Materials (CBOM) lifecycle management",
                "Deploy quantum-safe VPN solutions based on IKEv2 with PQC extensions"
            ]
        }
    }

    return report


@router.get("/reports/badge/{target}")
async def get_quantum_badge(target: str):
    """Get the quantum-safe badge/label for a specific target."""
    from app.routers.scanner import scan_jobs

    # Search all jobs for the target
    for job in scan_jobs.values():
        for result in job.get("results", []):
            if result.get("target") == target:
                pqc = result.get("pqc_assessment", {})
                return {
                    "target": target,
                    "status": pqc.get("status"),
                    "label": pqc.get("label"),
                    "score": pqc.get("score"),
                    "badge_color": pqc.get("badge_color"),
                    "issued_at": result.get("timestamp"),
                    "valid_algorithms": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-192s"],
                    "nist_compliant": pqc.get("status") in ["QUANTUM_SAFE", "PQC_READY"]
                }

    raise HTTPException(status_code=404, detail="Target not found in any completed scan")
