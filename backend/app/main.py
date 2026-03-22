from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scanner, reports, health
from app.routers import auth, history
from app.database import init_db

app = FastAPI(
    title="QuantumShield PQC Scanner API",
    description="Post-Quantum Cryptography Readiness Scanner — NIST FIPS 203/204/205",
    version="2.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup — create tables and seed default users
@app.on_event("startup")
def startup():
    init_db()

app.include_router(health.router,   prefix="/api/v1", tags=["Health"])
app.include_router(auth.router)
app.include_router(scanner.router,  prefix="/api/v1", tags=["Scanner"])
app.include_router(history.router)
app.include_router(reports.router,  prefix="/api/v1", tags=["Reports"])

@app.get("/")
def root():
    return {
        "service": "QuantumShield PQC Scanner",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs",
    }
