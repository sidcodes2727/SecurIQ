"""
Analysis API routes.
Handles PCAP analysis, security assessment, ML classification, and reports.
"""
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException

from backend.analyzers.pcap_parser import parse_pcap
from backend.analyzers.ipsec_analyzer import analyze_ipsec
from backend.analyzers.flow_extractor import extract_flow_features
from backend.ml.model import classifier
from backend.security.scoring_engine import assess_security
from backend.security.threat_matrix import generate_threat_matrix
from backend.reports.generator import generate_executive_report, generate_technical_report
from backend.routes.upload import uploaded_files
from backend.config import SAMPLE_DIR

router = APIRouter(prefix="/api", tags=["analysis"])

# In-memory storage for analysis results
analysis_results: dict[str, dict] = {}


def _resolve_file_path(file_id: str) -> str:
    """Resolve file_id to actual file path."""
    # Check uploads
    if file_id in uploaded_files:
        return uploaded_files[file_id]["path"]
    
    # Check samples
    if SAMPLE_DIR.exists():
        for f in SAMPLE_DIR.glob("*.pcap"):
            if f.stem == file_id:
                return str(f)
    
    raise HTTPException(status_code=404, detail=f"File not found: {file_id}")


@router.post("/analyze/{file_id}")
async def run_analysis(file_id: str):
    """Run complete analysis pipeline on a PCAP file."""
    filepath = _resolve_file_path(file_id)
    
    try:
        # Step 1: Parse PCAP
        parsed_data = parse_pcap(filepath)
        
        # Step 2: IPsec analysis
        ipsec_analysis = analyze_ipsec(parsed_data)
        
        # Step 3: Extract flow features
        flow_features = extract_flow_features(parsed_data)
        
        # Step 4: ML classification
        classification = []
        if flow_features and classifier.is_trained:
            classification = classifier.predict(flow_features)
        
        # Step 5: Security assessment
        security = assess_security(ipsec_analysis)
        
        # Step 6: Threat matrix
        threat_matrix = generate_threat_matrix(security.get("findings", []))
        
        # Step 7: Generate reports
        executive_report = generate_executive_report(
            ipsec_analysis, security, classification, threat_matrix
        )
        technical_report = generate_technical_report(
            parsed_data, ipsec_analysis, security,
            classification, threat_matrix, classifier.get_model_info()
        )
        
        # Store results
        analysis_id = str(uuid.uuid4())[:8]
        analysis_results[analysis_id] = {
            "analysis_id": analysis_id,
            "file_id": file_id,
            "parsed_data": parsed_data,
            "ipsec_analysis": ipsec_analysis,
            "flow_features": flow_features,
            "classification": classification,
            "security": security,
            "threat_matrix": threat_matrix,
            "executive_report": executive_report,
            "technical_report": technical_report,
        }
        
        return {
            "analysis_id": analysis_id,
            "status": "complete",
            "summary": {
                "total_packets": parsed_data["metadata"]["total_packets"],
                "ike_detected": ipsec_analysis.get("ike_analysis", {}).get("detected", False),
                "esp_detected": ipsec_analysis.get("esp_analysis", {}).get("detected", False),
                "security_score": security.get("overall_score", 0),
                "risk_level": security.get("risk_level", "Unknown"),
                "classified_flows": len(classification),
                "findings_count": len(security.get("findings", [])),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get full analysis results."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    result = analysis_results[analysis_id]
    return {
        "analysis_id": analysis_id,
        "ipsec_analysis": result["ipsec_analysis"],
        "security": result["security"],
        "classification": result["classification"],
        "threat_matrix": result["threat_matrix"],
        "flow_features_count": len(result["flow_features"]),
        "parsed_metadata": result["parsed_data"]["metadata"],
        "parsed_summary": result["parsed_data"]["summary"],
    }


@router.get("/analysis/{analysis_id}/packets")
async def get_packets(analysis_id: str, limit: int = 100, offset: int = 0):
    """Get parsed packet details."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    packets = analysis_results[analysis_id]["parsed_data"]["packets"]
    return {
        "total": len(packets),
        "offset": offset,
        "limit": limit,
        "packets": packets[offset:offset + limit],
    }


@router.get("/security/{analysis_id}")
async def get_security(analysis_id: str):
    """Get security assessment results."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_results[analysis_id]["security"]


@router.get("/security/{analysis_id}/findings")
async def get_findings(analysis_id: str):
    """Get security findings."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    findings = analysis_results[analysis_id]["security"].get("findings", [])
    return {"findings": findings, "count": len(findings)}


@router.get("/security/{analysis_id}/threat-matrix")
async def get_threat_matrix(analysis_id: str):
    """Get threat matrix."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_results[analysis_id]["threat_matrix"]


@router.get("/reports/{analysis_id}/executive")
async def get_executive_report(analysis_id: str):
    """Get executive report."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_results[analysis_id]["executive_report"]


@router.get("/reports/{analysis_id}/technical")
async def get_technical_report(analysis_id: str):
    """Get technical report."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_results[analysis_id]["technical_report"]


@router.get("/ml/classify/{analysis_id}")
async def classify_traffic(analysis_id: str):
    """Run/get ML traffic classification for an analysis."""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    result = analysis_results[analysis_id]
    
    if not result["classification"] and result["flow_features"]:
        if not classifier.is_trained:
            return {
                "status": "model_not_trained",
                "message": "ML model is not trained. Generate dataset and train first.",
            }
        result["classification"] = classifier.predict(result["flow_features"])
    
    return {
        "classification": result["classification"],
        "flow_count": len(result["flow_features"]),
        "model_info": classifier.get_model_info(),
    }


@router.get("/ml/model-info")
async def get_model_info():
    """Get ML model information."""
    return classifier.get_model_info()


@router.post("/ml/train")
async def train_model():
    """Train/retrain the ML model."""
    try:
        from backend.ml.synthetic_data import generate_dataset
        
        # Generate dataset if needed
        dataset_path = Path(classifier.metrics.get("dataset_path", "")) 
        from backend.config import DATASET_DIR
        dataset_file = DATASET_DIR / "synthetic_dataset.json"
        
        if not dataset_file.exists():
            generate_dataset()
        
        # Train
        metrics = classifier.train()
        
        return {
            "status": "success",
            "metrics": metrics,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.post("/dataset/generate")
async def generate_dataset_endpoint():
    """Generate synthetic training dataset."""
    try:
        from backend.ml.synthetic_data import generate_dataset
        result = generate_dataset()
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


@router.get("/dataset/info")
async def get_dataset_info():
    """Get dataset information."""
    import json
    from backend.config import DATASET_DIR
    
    dataset_file = DATASET_DIR / "synthetic_dataset.json"
    if not dataset_file.exists():
        return {"exists": False, "message": "No dataset generated yet."}
    
    with open(dataset_file) as f:
        data = json.load(f)
    
    metadata = data.get("metadata", {})
    return {
        "exists": True,
        **metadata,
    }


@router.post("/samples/generate")
async def generate_samples():
    """Generate sample PCAP files."""
    try:
        from backend.sample_data.generate_sample_pcap import generate_all_samples
        files = generate_all_samples()
        return {
            "status": "success",
            "files": [Path(f).name for f in files],
            "count": len(files),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


@router.get("/analyses")
async def list_analyses():
    """List all completed analyses."""
    analyses = []
    for aid, data in analysis_results.items():
        analyses.append({
            "analysis_id": aid,
            "file_id": data["file_id"],
            "total_packets": data["parsed_data"]["metadata"]["total_packets"],
            "security_score": data["security"].get("overall_score", 0),
            "risk_level": data["security"].get("risk_level", "Unknown"),
        })
    return {"analyses": analyses, "count": len(analyses)}
