from fastapi import FastAPI

app = FastAPI(
    title="VerifiX Security Scanner",
    description="AI-assisted application security analysis",
    version="0.1.0",
)


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