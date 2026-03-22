from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scanner, reports, health

app = FastAPI(
    title="QuantumShield PQC Scanner API",
    description="Cryptographic Bill of Materials & Post-Quantum Cryptography Readiness Scanner",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(scanner.router, prefix="/api/v1", tags=["Scanner"])
app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])

@app.get("/")
def root():
    return {"service": "QuantumShield PQC Scanner", "version": "1.0.0", "status": "operational"}
