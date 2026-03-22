from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, validator
from typing import List, Optional
import asyncio
import concurrent.futures
import re
from app.services.scanner_service import scan_tls_target, check_http_security_headers

router = APIRouter()

# In-memory job store (use Redis in production)
scan_jobs = {}

class ScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    include_headers: bool = True
    scan_name: Optional[str] = None

    @validator('targets')
    def validate_targets(cls, v):
        if len(v) > 20:
            raise ValueError('Maximum 20 targets per scan')
        validated = []
        for target in v:
            # Strip protocol
            target = re.sub(r'^https?://', '', target).split('/')[0].strip()
            if not target:
                continue
            validated.append(target)
        return validated

class SingleScanRequest(BaseModel):
    target: str
    port: int = 443

def run_scan_job(job_id: str, targets: list, port: int, include_headers: bool):
    """Background job to scan multiple targets."""
    scan_jobs[job_id]["status"] = "running"
    results = []
    total = len(targets)

    for idx, target in enumerate(targets):
        scan_jobs[job_id]["progress"] = {
            "current": idx + 1,
            "total": total,
            "current_target": target
        }
        try:
            result = scan_tls_target(target, port)
            if include_headers:
                result["http_headers"] = check_http_security_headers(target, port)
            results.append(result)
        except Exception as e:
            results.append({
                "target": target,
                "status": "error",
                "errors": [str(e)]
            })

    scan_jobs[job_id]["status"] = "completed"
    scan_jobs[job_id]["results"] = results
    scan_jobs[job_id]["progress"]["current"] = total

    # Generate summary
    pqc_statuses = [r.get("pqc_assessment", {}).get("status", "UNKNOWN") for r in results]
    scan_jobs[job_id]["summary"] = {
        "total_scanned": len(results),
        "quantum_safe": pqc_statuses.count("QUANTUM_SAFE"),
        "pqc_ready": pqc_statuses.count("PQC_READY"),
        "transitioning": pqc_statuses.count("TRANSITIONING"),
        "vulnerable": pqc_statuses.count("VULNERABLE"),
        "errors": sum(1 for r in results if r.get("status") == "error")
    }


@router.post("/scan/quick")
async def quick_scan(request: SingleScanRequest):
    """Quick single-target scan (synchronous)."""
    target = re.sub(r'^https?://', '', request.target).split('/')[0].strip()
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, scan_tls_target, target, request.port)
        headers = await loop.run_in_executor(pool, check_http_security_headers, target, request.port)

    result["http_headers"] = headers
    return result


@router.post("/scan/batch")
async def batch_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a batch scan job (asynchronous)."""
    import uuid
    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "job_id": job_id,
        "scan_name": request.scan_name or f"Batch Scan - {len(request.targets)} targets",
        "status": "queued",
        "targets": request.targets,
        "progress": {"current": 0, "total": len(request.targets), "current_target": ""},
        "results": [],
        "summary": {}
    }

    background_tasks.add_task(
        run_scan_job,
        job_id,
        request.targets,
        request.port,
        request.include_headers
    )

    return {"job_id": job_id, "status": "queued", "targets_count": len(request.targets)}


@router.get("/scan/job/{job_id}")
async def get_scan_job(job_id: str):
    """Get the status and results of a scan job."""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return scan_jobs[job_id]


@router.get("/scan/jobs")
async def list_scan_jobs():
    """List all scan jobs."""
    return [
        {
            "job_id": v["job_id"],
            "scan_name": v.get("scan_name"),
            "status": v["status"],
            "targets_count": len(v.get("targets", [])),
            "summary": v.get("summary", {})
        }
        for v in scan_jobs.values()
    ]


@router.get("/algorithms/pqc")
async def get_pqc_algorithms():
    """Get list of NIST-standardized PQC algorithms."""
    from app.services.scanner_service import PQC_ALGORITHMS, VULNERABLE_ALGORITHMS, PQC_RECOMMENDATIONS
    return {
        "pqc_algorithms": PQC_ALGORITHMS,
        "vulnerable_algorithms": VULNERABLE_ALGORITHMS,
        "recommendations": PQC_RECOMMENDATIONS,
        "nist_standards": {
            "FIPS_203": "ML-KEM (Module Lattice-based Key Encapsulation Mechanism)",
            "FIPS_204": "ML-DSA (Module Lattice-based Digital Signature Algorithm)",
            "FIPS_205": "SLH-DSA (Stateless Hash-based Digital Signature Algorithm)"
        }
    }
