"""
FastAPI application entry point — Phase 2 (Full Detection Engine).
AI Security Scanner — OWASP-Based Vulnerability Assessment System v1.0
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, File, HTTPException, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.config import settings
from app.core.logging import logger
from app.models.scan_response import ScanResponse
from app.services import scan_manager
from app.services.reporter import generate_pdf_report
from fastapi.responses import FileResponse, StreamingResponse
from pathlib import Path
import json


# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description="OWASP-Based AI Vulnerability Assessment System with LLM-Powered Detection",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class TextInput(BaseModel):
    content: str
    filename: str = "pasted_text.txt"

@app.get("/health", tags=["Health"])
async def health_check():
    """Liveness probe."""
    return {
        "status": "healthy",
        "service": settings.APP_TITLE,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    """Serve PDF report."""
    file_path = Path(settings.REPORT_DIR) / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(file_path, media_type="application/pdf", filename=filename)

@app.post("/api/scan", response_model=ScanResponse | dict, tags=["Scan"])
async def scan_file(files: list[UploadFile] = File(...)):
    """
    Hybrid vulnerability scan endpoint — all 10 OWASP LLM 2025 categories.
    Supports single or multiple file uploads.
    """
    # If single file passed (backward compat or single upload), wrap in list?
    # FastAPI handles List[UploadFile] automatically.
    
    overall_start_time = time.perf_counter()
    
    # Delegate to scan_manager
    scan_results = await scan_manager.scan_files_concurrently(files)

    # If only 1 file, return just that ScaResponse (backward compatibility for UI? 
    # No, requirement says "Return ... files: [...], overall: {...}". 
    # But checking constraints: "Keep single-file behavior working."
    # If the UI expects ScanResponse for single file, I might need to check.
    # However, the requirement says "Return a response schema like: files: ..., overall: ...".
    # I will stick to the new MultiFilesResponse schema for everything to be consistent, implies UI update.
    
    # Calculate aggregated key metrics
    max_risk = 0
    total_findings = 0
    for r in scan_results:
        max_risk = max(max_risk, r.risk_score)
        total_findings += r.total_findings
    
    # Map max_risk to string level
    overall_level = "Low"
    if max_risk >= 76: overall_level = "Critical"
    elif max_risk >= 51: overall_level = "High"
    elif max_risk >= 26: overall_level = "Medium"

    overall_data = {
        "risk_score": max_risk,
        "risk_level": overall_level,
        "total_files": len(files),
        "total_findings": total_findings,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "total_duration": round(time.perf_counter() - overall_start_time, 3)
    }

    # Generate PDF Report
    try:
        batch_id = f"scan-{uuid.uuid4()}"
        pdf_filename = f"{batch_id}.pdf"
        report_path = Path(settings.REPORT_DIR) / pdf_filename
        
        report_data = {
            "files": scan_results,
            "overall": overall_data
        }
        
        generate_pdf_report(report_data, str(report_path))
        pdf_url = f"/api/reports/{pdf_filename}"
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        pdf_url = None

    return {
        "files": scan_results,
        "overall": overall_data,
        "pdf_url": pdf_url
    }


@app.post("/api/scan-text", response_model=ScanResponse | dict, tags=["Scan"])
async def scan_text(input: TextInput):
    """
    Scan raw text content directly.
    """
    scan_results = [await scan_manager.scan_text_content(input.content, input.filename)]

    # Calculate aggregated key metrics (duplicated from scan_file for now)
    max_risk = 0
    total_findings = 0
    for r in scan_results:
        max_risk = max(max_risk, r.risk_score)
        total_findings += r.total_findings
    
    overall_level = "Low"
    if max_risk >= 76: overall_level = "Critical"
    elif max_risk >= 51: overall_level = "High"
    elif max_risk >= 26: overall_level = "Medium"

    overall_data = {
        "risk_score": max_risk,
        "risk_level": overall_level,
        "total_files": 1,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Generate PDF Report
    try:
        batch_id = f"scan-{uuid.uuid4()}"
        pdf_filename = f"{batch_id}.pdf"
        report_path = Path(settings.REPORT_DIR) / pdf_filename
        
        report_data = {
            "files": scan_results,
            "overall": overall_data
        }
        
        generate_pdf_report(report_data, str(report_path))
        pdf_url = f"/api/reports/{pdf_filename}"
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        pdf_url = None

    return {
        "files": scan_results,
        "overall": overall_data,
        "pdf_url": pdf_url
    }


@app.post("/api/scan/progress", tags=["Scan"])
async def scan_with_progress(files: list[UploadFile] = File(...)):
    """
    Streaming content endpoint. Returns NDJSON events for progress updates.
    """
    queue = asyncio.Queue()

    async def producer():
        try:
            # This returns the final results, but we only care about the side-effect (events in queue)
            # scan_manager.scan_files_concurrently calls process_single_file which puts events
            await scan_manager.scan_files_concurrently(files, queue)
        except Exception as e:
            logger.error(f"Streaming scan failed: {e}")
            await queue.put({"type": "error", "message": str(e)})
        finally:
            await queue.put(None) # Signal done

    async def consumer():
        # Start producer task
        asyncio.create_task(producer())
        
        while True:
            item = await queue.get()
            if item is None:
                break
            # Yield NDJSON line
            yield json.dumps(item) + "\n"

    return StreamingResponse(consumer(), media_type="application/x-ndjson")
