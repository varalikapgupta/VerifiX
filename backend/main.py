
from pathlib import Path

from fastapi import FastAPI, HTTPException

from static_scanner import scan_file

app = FastAPI(
    title="VerifiX Security Scanner",
    description="AI-assisted application security analysis",
    version="0.2.0",
)

BASE_DIR = Path(__file__).resolve().parent
TARGET_FILE = BASE_DIR / "vulnerable_app.py"


@app.get("/")
def home():
    return {
        "project": "VerifiX",
        "status": "running",
        "role": "backend",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan")
def run_scan():
    try:
        findings = scan_file(TARGET_FILE)
        return {
            "target": TARGET_FILE.name,
            "finding_count": len(findings),
            "findings": findings,
        }
    except (OSError, SyntaxError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {exc}",
        ) from exc
