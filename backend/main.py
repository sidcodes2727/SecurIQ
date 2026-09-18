"""
IPsec VPN Protocol Analyzer - FastAPI Application
Main entry point for the backend server.
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.routes.upload import router as upload_router
from backend.routes.analysis import router as analysis_router
from backend.ml.model import classifier
from backend.config import DATA_DIR, SAMPLE_DIR, DATASET_DIR

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Starting IPsec VPN Analyzer backend...")
    
    # Generate sample data on startup if not exists
    try:
        if not any(SAMPLE_DIR.glob("*.pcap")):
            logger.info("Generating sample PCAP files...")
            from backend.sample_data.generate_sample_pcap import generate_all_samples
            files = generate_all_samples()
            logger.info(f"Generated {len(files)} sample PCAP files")
    except Exception as e:
        logger.warning(f"Could not generate sample PCAPs: {e}")
    
    # Generate dataset and train model if not exists
    try:
        dataset_file = DATASET_DIR / "synthetic_dataset.json"
        if not dataset_file.exists():
            logger.info("Generating synthetic dataset...")
            from backend.ml.synthetic_data import generate_dataset
            generate_dataset()
            logger.info("Synthetic dataset generated")
        
        if not classifier.is_trained:
            logger.info("Training ML model...")
            metrics = classifier.train()
            logger.info(f"Model trained. Accuracy: {metrics['accuracy']}")
    except Exception as e:
        logger.warning(f"Could not train model on startup: {e}")
    
    yield
    
    logger.info("Shutting down IPsec VPN Analyzer backend...")


app = FastAPI(
    title="IPsec VPN Protocol Analyzer",
    description="AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(upload_router)
app.include_router(analysis_router)


@app.get("/")
async def root():
    return {
        "name": "IPsec VPN Protocol Analyzer",
        "version": "1.0.0",
        "status": "running",
        "model_trained": classifier.is_trained,
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "model_trained": classifier.is_trained,
        "sample_files": len(list(SAMPLE_DIR.glob("*.pcap"))) if SAMPLE_DIR.exists() else 0,
    }
