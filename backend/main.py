"""
SecurIQ — AI-Powered IPsec VPN Protocol Analyzer: FastAPI application entry point.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.bootstrap import start_background_bootstrap, state
from backend.config import SAMPLE_DIR
from backend.ml.model import classifier
from backend.routes.analysis import router as analysis_router
from backend.routes.capture import router as capture_router
from backend.routes.intel import router as intel_router
from backend.routes.live import router as live_router
from backend.realtime.manager import manager as live_manager
from backend.routes.testbed import router as testbed_router
from backend.routes.upload import router as upload_router
from backend.storage import sample_manifest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

VERSION = "3.0.0"
DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SecurIQ backend %s", VERSION)
    start_background_bootstrap()
    yield
    for session in live_manager.list():
        if session["status"] in ("starting", "running"):
            live_manager.get(session["id"]).stop()
    logger.info("Shutting down SecurIQ backend")


app = FastAPI(
    title="SecurIQ — IPsec VPN Protocol Analyzer",
    description="AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
    version=VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("SECURIQ_CORS_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(testbed_router)
app.include_router(capture_router)
app.include_router(live_router)
app.include_router(intel_router)


@app.get("/")
def root():
    return {"name": "SecurIQ IPsec VPN Protocol Analyzer", "version": VERSION, "status": "running",
            "model_trained": classifier.is_trained}


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "version": VERSION,
        "model_trained": classifier.is_trained,
        "model_training": state["model_training"],
        "model_error": state["model_error"],
        "samples_ready": state["samples_ready"],
        "sample_files": len(sample_manifest().get("samples", {})) if SAMPLE_DIR.exists() else 0,
    }
