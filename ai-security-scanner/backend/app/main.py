from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, UploadFile, File
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/scan")
async def scan(files: list[UploadFile] = File(...)):
    config = {}
    for file in files:
        if file.filename.endswith('.json'):
            content = await file.read()
            config = json.loads(content.decode())
    
    # Extract prompt for analysis
    prompt = config.get("agent_config", {}).get("prompt_template", "")
    
    # OWASP LLM-01: Prompt Injection detection
    prompt_injection_keywords = ["ignore previous", "forget", "override", "system:", "format"]
    is_prompt_injection_risk = any(keyword in prompt.lower() for keyword in prompt_injection_keywords)
    
    # OWASP LLM-02: Data Leakage detection
    sensitive_keywords = ["password", "api_key", "secret", "token", "database"]
    tools = config.get("agent_config", {}).get("tools", [])
    has_sensitive_data = any(keyword in prompt.lower() for keyword in sensitive_keywords)
    has_external_calls = any("http" in str(tool).lower() for tool in tools)

    is_data_leakage_risk = has_sensitive_data or has_external_calls

    # OWASP LLM-06: Excessive Agency
    permissions = config.get("agent_config", {}).get("permissions", [])
    tools = config.get("agent_config", {}).get("tools", [])

    dangerous_perms = ["db_write", "file_write", "exec", "root"]
    any_perm_dangerous = any(any(perm in str(p).lower() for perm in dangerous_perms) for p in permissions)
    any_tool_dangerous = any("filesystem" in str(t).lower() or "exec" in str(t).lower() for t in tools)
    is_excessive_agency = any_perm_dangerous or any_tool_dangerous

    excessive_agency_risk = is_excessive_agency

    # OWASP LLM-08: Insecure Output Handling
    output_handling = config.get("agent_config", {}).get("output_handling", "")
    is_insecure_output = (
        "db" in output_handling.lower() or 
        "exec" in output_handling.lower() or
        any("http" in str(t).lower() and "output" in str(t).lower() for t in tools)
    )

    insecure_output_risk = is_insecure_output

    # Calculate total score first
    total_score = sum([
        40 if is_prompt_injection_risk else 0,
        30 if is_data_leakage_risk else 0,
        20 if excessive_agency_risk else 0,
        20 if insecure_output_risk else 0
    ])

    # Map to risk level (PRD requirement)
    if total_score <= 30:
        risk_level = "LOW"
    elif total_score <= 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    


    return {
        "status": "FULL SCAN COMPLETE",
        "files_received": len(files),  
        "config_keys": list(config.keys()), 
        "agent_name": config.get("agent_config", {}).get("name"),
        "prompt": prompt,
        "findings": {
            "prompt_injection": is_prompt_injection_risk,
            "data_leakage": is_data_leakage_risk,
            "excessive_agency": excessive_agency_risk,
            "insecure_output": insecure_output_risk
        },
        "risk_score_breakdown": {
            "llm01_prompt_injection": 40 if is_prompt_injection_risk else 0,
            "llm02_data_leakage": 30 if is_data_leakage_risk else 0,
            "llm06_excessive_agency": 20 if excessive_agency_risk else 0,
            "llm08_insecure_output": 20 if insecure_output_risk else 0
        },
        "total_risk_score": total_score,
        "risk_level": risk_level
    }


@app.get("/")
def root():
    return {"message": "OWASP AI Security Scanner - Ready for agent analysis"}
