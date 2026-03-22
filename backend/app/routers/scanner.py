"""
QuantumShield — Scanner Router
Scans are saved to DB. Auth optional for quick scan, required for history.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator
from typing import List, Optional
import asyncio
import concurrent.futures
import re
import uuid
import json

from app.services.scanner_service import scan_tls_target, check_http_security_headers, PQC_ALGORITHMS
from app.database import get_db, ScanHistory
from app.routers.auth import get_current_user, log_action, require_operator_or_admin
from app.database import User

router    = APIRouter()
scan_jobs = {}  # in-memory job store


# ── Schemas ───────────────────────────────────────────────────────────────────
class SingleScanRequest(BaseModel):
    target: str
    port: int = 443

class ScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    include_headers: bool = True
    scan_name: Optional[str] = None

    @validator("targets")
    def validate_targets(cls, v):
        if len(v) > 20:
            raise ValueError("Maximum 20 targets per scan")
        return [re.sub(r"^https?://", "", t).split("/")[0].strip() for t in v if t.strip()]


# ── Helpers ───────────────────────────────────────────────────────────────────
def _save_result(db: Session, result: dict, user: Optional[User]):
    """Persist a scan result to the database."""
    try:
        tls   = result.get("tls_info", {})
        pqc   = result.get("pqc_assessment", {})
        record = ScanHistory(
            scan_id     = result.get("scan_id", str(uuid.uuid4())),
            user_id     = user.id if user else None,
            username    = user.username if user else "anonymous",
            target      = result.get("target", ""),
            port        = result.get("port", 443),
            pqc_score   = pqc.get("score"),
            pqc_status  = pqc.get("status"),
            tls_version = tls.get("tls_version"),
            cipher_suite= tls.get("cipher_suite"),
            result_json = json.dumps(result, default=str),
        )
        db.add(record)
        db.commit()
    except Exception:
        pass  # never fail a scan because of DB issues


def _run_scan_job(job_id: str, targets: list, port: int, user_id: Optional[int],
                  username: Optional[str]):
    from app.database import SessionLocal
    db = SessionLocal()
    scan_jobs[job_id]["status"] = "running"
    results = []

    for idx, target in enumerate(targets):
        scan_jobs[job_id]["progress"] = {
            "current": idx + 1, "total": len(targets), "current_target": target
        }
        try:
            r = scan_tls_target(target, port)
            r["http_headers"] = check_http_security_headers(target, port)

            # fake user obj for saving
            class _U:
                id = user_id
                username = username or "anonymous"

            _save_result(db, r, _U() if user_id else None)
            results.append(r)
        except Exception as e:
            results.append({"target": target, "status": "error", "errors": [str(e)]})

    scan_jobs[job_id]["status"]  = "completed"
    scan_jobs[job_id]["results"] = results
    scan_jobs[job_id]["progress"]["current"] = len(targets)

    statuses = [r.get("pqc_assessment", {}).get("status", "UNKNOWN") for r in results]
    scan_jobs[job_id]["summary"] = {
        "total_scanned": len(results),
        "quantum_safe":  statuses.count("QUANTUM_SAFE"),
        "pqc_ready":     statuses.count("PQC_READY"),
        "transitioning": statuses.count("TRANSITIONING"),
        "vulnerable":    statuses.count("VULNERABLE"),
        "errors":        sum(1 for r in results if r.get("status") == "error"),
    }
    db.close()


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/scan/quick")
async def quick_scan(request: Request, payload: SingleScanRequest,
                     db: Session = Depends(get_db),
                     user: Optional[User] = Depends(get_current_user)):
    target = re.sub(r"^https?://", "", payload.target).split("/")[0].strip()
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result  = await loop.run_in_executor(pool, scan_tls_target, target, payload.port)
        headers = await loop.run_in_executor(pool, check_http_security_headers, target, payload.port)

    result["http_headers"] = headers

    # Save to DB
    _save_result(db, result, user)
    if user:
        log_action(db, user, "SCAN", target=target,
                   ip=request.client.host if request.client else None)

    return result


@router.post("/scan/batch", dependencies=[Depends(require_operator_or_admin)])
async def batch_scan(payload: ScanRequest, background_tasks: BackgroundTasks,
                     user: User = Depends(require_operator_or_admin),
                     db: Session = Depends(get_db)):
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "job_id": job_id,
        "scan_name": payload.scan_name or f"Batch — {len(payload.targets)} targets",
        "status": "queued",
        "targets": payload.targets,
        "progress": {"current": 0, "total": len(payload.targets), "current_target": ""},
        "results": [],
        "summary": {},
    }
    background_tasks.add_task(_run_scan_job, job_id, payload.targets,
                              payload.port, user.id, user.username)
    log_action(db, user, "BATCH_SCAN", details=f"{len(payload.targets)} targets")
    return {"job_id": job_id, "status": "queued", "targets_count": len(payload.targets)}


@router.get("/scan/job/{job_id}")
async def get_job(job_id: str):
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return scan_jobs[job_id]


@router.get("/scan/jobs", dependencies=[Depends(require_operator_or_admin)])
async def list_jobs():
    return [{"job_id":v["job_id"],"scan_name":v.get("scan_name"),
             "status":v["status"],"targets_count":len(v.get("targets",[])),
             "summary":v.get("summary",{})} for v in scan_jobs.values()]


@router.get("/algorithms/pqc")
async def pqc_algorithms():
    from app.services.scanner_service import PQC_RECOMMENDATIONS
    return {
        "pqc_algorithms": PQC_ALGORITHMS,
        "recommendations": PQC_RECOMMENDATIONS,
        "nist_standards": {
            "FIPS_203": "ML-KEM — Key Encapsulation Mechanism",
            "FIPS_204": "ML-DSA — Digital Signature Algorithm",
            "FIPS_205": "SLH-DSA — Stateless Hash-based Signatures",
        },
    }
