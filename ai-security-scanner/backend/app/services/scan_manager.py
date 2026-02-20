import asyncio
import time
import uuid
import uuid
from datetime import datetime, timezone

from fastapi import UploadFile
from app.core.config import settings
from app.core.logging import logger
from app.core.security import check_file_size, sanitize_content, validate_upload
from app.models.scan_response import ScanResponse, VulnerabilityFinding
from app.services import detector_llm, detector_rule
from app.services.parser import parse_file
from app.services.scorer import calculate_risk_score

# Global concurrency limit
_SCAN_SEMAPHORE = asyncio.Semaphore(3)

async def process_single_file(file: UploadFile, progress_queue: asyncio.Queue = None) -> ScanResponse:
    async with _SCAN_SEMAPHORE:
        file_type = validate_upload(file)
        content = await file.read()
        check_file_size(content)
        
        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            logger.error("File processing failed | filename=%s | error=UnicodeDecodeError", file.filename)
            return ScanResponse(
                scan_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                file_name=file.filename or "unknown",
                file_type=file_type,
                risk_score=0,
                risk_level="Low",
                summary="Failed to read file (encoding error).",
                findings=[],
                scan_duration=0.1
            )

        text_content = sanitize_content(text_content)
        if progress_queue:
            await progress_queue.put({
                "type": "file_start",
                "filename": file.filename,
                "timestamp": datetime.now().isoformat()
            })
            
        result = await _scan_content(text_content, file.filename, file_type, progress_queue)
        
        if progress_queue:
            # Try to serialize using model_dump (Pydantic v2) or dict (v1)
            try:
                result_dict = result.model_dump()
            except AttributeError:
                result_dict = result.dict()
            
            await progress_queue.put({
                "type": "file_complete",
                "filename": file.filename,
                "scan_id": result.scan_id,
                "risk_score": result.risk_score,
                "result": result_dict
            })
        return result

async def _scan_content(text_content: str, filename: str, file_type: str, progress_queue: asyncio.Queue = None) -> ScanResponse:
    start_time = time.perf_counter()
    timings = {}
    scan_id = str(uuid.uuid4())
    logger.info("Scan started | scan_id=%s | filename=%s", scan_id, filename)

    # Parser
    t0 = time.perf_counter()
    parsed = parse_file(text_content, file_type)
    timings["parser"] = round(time.perf_counter() - t0, 3)
    if progress_queue:
        await progress_queue.put({"type": "progress", "filename": filename, "phase": "parsing", "status": "done"})

    # Rules
    t1 = time.perf_counter()
    rule_results = await asyncio.gather(
        detector_rule.detect_prompt_injection_rules(parsed),
        detector_rule.detect_sensitive_info_rules(parsed),
        detector_rule.detect_improper_output_rules(parsed),
        detector_rule.detect_excessive_agency_rules(parsed),
        detector_rule.detect_supply_chain_rules(parsed),
        detector_rule.detect_data_poisoning_rules(parsed),
        detector_rule.detect_system_prompt_leakage_rules(parsed),
        detector_rule.detect_vector_embedding_rules(parsed),
        detector_rule.detect_misinformation_rules(parsed),
        detector_rule.detect_unbounded_consumption_rules(parsed),
    )
    rule_findings = [f for sublist in rule_results for f in sublist]
    timings["rules"] = round(time.perf_counter() - t1, 3)
    if progress_queue:
        await progress_queue.put({"type": "progress", "filename": filename, "phase": "rules", "status": "done"})

    # LLM
    t2 = time.perf_counter()
    try:
        llm_findings = await detector_llm.run_all_llm_scans(parsed)
    except Exception as exc:
        logger.error("LLM detection failed | %s | scan_id=%s", exc, scan_id)
        llm_findings = []
    timings["llm_engine"] = round(time.perf_counter() - t2, 3)
    if progress_queue:
        await progress_queue.put({"type": "progress", "filename": filename, "phase": "llm", "status": "done"})

    # Merge
    t3 = time.perf_counter()
    all_raw = rule_findings + llm_findings
    findings = []
    for raw in all_raw:
        try:
             raw.setdefault("description", "No description.")
             raw.setdefault("remediation", "Review manually.")
             findings.append(VulnerabilityFinding(**raw))
        except:
             pass

    # Score
    risk_data = calculate_risk_score(findings)
    duration = round(time.perf_counter() - start_time, 3)
    timings["total"] = duration
    timings["post_processing"] = round(time.perf_counter() - t3, 3)

    return ScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        file_name=filename or "unknown",
        file_type=file_type,
        risk_score=risk_data["risk_score"],
        risk_level=risk_data["risk_level"],
        summary=risk_data["summary"],
        findings=findings,
        breakdown_by_category=risk_data["breakdown_by_category"],
        total_findings=len(findings),
        critical_severity_count=risk_data["critical_severity_count"],
        high_severity_count=risk_data["high_severity_count"],
        medium_severity_count=risk_data["medium_severity_count"],
        low_severity_count=risk_data["low_severity_count"],
        scan_duration=duration,
        timings=timings,
    )

async def scan_files_concurrently(files: list[UploadFile], progress_queue: asyncio.Queue = None) -> list[ScanResponse]:
    tasks = [process_single_file(file, progress_queue) for file in files]
    return await asyncio.gather(*tasks)

async def scan_text_content(content: str, filename: str) -> ScanResponse:
    # Wrapper for text scan
    return await _scan_content(content, filename, ".txt")
