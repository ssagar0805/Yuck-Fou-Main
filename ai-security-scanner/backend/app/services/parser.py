"""
File parsing service.
Accepts raw file content + type and extracts security-relevant sections
into a unified structure for downstream detection services.

OWASP 2025 — Normalized output keys:
  system_prompt     : str | None           — LLM01, LLM02, LLM07
  tools             : list[dict]           — LLM06
  permissions       : list[str]            — LLM06
  output_handlers   : list[dict]           — LLM05
  model_supply_chain: dict                 — LLM03
  training_ingestion: dict                 — LLM04
  rag_vector        : dict                 — LLM08
  policy_misinfo    : dict                 — LLM09
  resource_limits   : dict                 — LLM10
  raw_content       : str                  — always present (LLM fallback)
  
  # NEW: Workflow Graph (FR2)
  workflow_graph    : dict                 — nodes, edges, triggers, sinks (n8n/Flowise/LangGraph)
  external_calls    : list[dict]           — detected external URLs/APIs
"""

import json
import re
from typing import Any

import yaml

from app.core.logging import logger


# Keys we look for when extracting from JSON/YAML configs
PROMPT_KEYS = {
    "system_prompt", "system", "prompt", "instruction", "instructions",
    "systemPrompt", "system_message", "systemMessage", "preamble",
}
TOOL_KEYS = {
    "tools", "functions", "extensions", "capabilities",
    "actions", "skills",
    "nodes", # Sometimes tools are defined as nodes
}
PERMISSION_KEYS = {
    "permissions", "scopes", "access", "roles", "grants",
    "allow", "allowlist",
}
OUTPUT_HANDLER_KEYS = {
    "output", "output_handler", "outputHandler", "response_handler",
    "responseHandler", "post_process", "postProcess", "callback",
}

# Keys for NEW categories — we detect their presence at the TOP level of dicts
_SUPPLY_CHAIN_KEYS = {
    "model", "plugins", "dependencies", "adapters", "allow_remote_code",
    "allowRemoteCode", "checksum_verification", "checksumVerification",
    "sbom", "base_model", "baseModel",
}
_TRAINING_INGESTION_KEYS = {
    "pipeline", "data_sources", "dataSources", "auto_ingest",
    "autoIngest", "auto_ingest_to_training_set", "human_review_required",
    "humanReviewRequired", "data_validation", "dataValidation",
    "training", "finetune", "fine_tune", "fine_tuning", "controls",
}
_RAG_VECTOR_KEYS = {
    "rag", "vector_store", "vectorStore", "namespace_isolation",
    "namespaceIsolation", "allow_cross_namespace", "allowCrossNamespace",
    "auto_index_external_urls", "sanitize_documents", "retrieval", "retrieve",
    "embeddings", "knowledge_base", "knowledgeBase",
}
_RESOURCE_LIMIT_KEYS = {
    "rate_limit", "rateLimit", "rate_limit_per_minute", "quota", "daily_quota",
    "dailyQuota", "max_tokens", "max_output_tokens", "maxOutputTokens",
    "max_input_size", "maxInputSize", "timeout", "timeout_seconds",
    "timeoutSeconds", "retries", "retry", "max_retries", "maxRetries",
    "max_concurrent_requests", "maxConcurrentRequests", "throttle",
}



def get_line_number(content: str, substring: str, start_index: int = 0) -> int | None:
    """
    Find the line number (1-indexed) of the first occurrence of substring
    in content, optionally starting search at start_index.
    """
    if not substring:
        return None
    try:
        idx = content.find(substring, start_index)
        if idx == -1:
            return None
        # Count newlines up to idx
        return content.count('\n', 0, idx) + 1
    except Exception:
        return None


def parse_file(content: str, file_type: str) -> dict[str, Any]:
    """
    Parse uploaded file content and extract security-relevant sections.

    Returns a normalized dict with keys supporting all 10 OWASP categories.
    """
    result: dict[str, Any] = {
        # Original 4
        "system_prompt": None,
        "tools": [],
        "permissions": [],
        "output_handlers": [],
        # New 6 (one dict per category, empty = not detected)
        "model_supply_chain": {},
        "training_ingestion": {},
        "rag_vector": {},
        "policy_misinfo": {},
        "resource_limits": {},
        # FR2: Workflow Graph
        "workflow_graph": {
            "nodes": [],
            "edges": [],
            "trigger_nodes": [],
            "sink_nodes": []
        },
        "external_calls": [],
        # Always present fallback
        "raw_content": content,
    }

    try:
        if file_type == "json":
            _parse_json(content, result)
        elif file_type == "yaml":
            _parse_yaml(content, result)
        elif file_type == "txt":
            _parse_txt(content, result)
        elif file_type == "py":
            _parse_python(content, result)
        elif file_type == "js" or file_type == "ts":
            _parse_js(content, result)
        else:
            logger.warning("Unknown file_type '%s', falling back to raw content.", file_type)
    except Exception as exc:
        logger.warning("Parser error for file_type='%s': %s. Using raw content.", file_type, exc)

    # Final pass: always scan raw_content for policy_misinfo signals (TXT files)
    if not result["policy_misinfo"]:
        result["policy_misinfo"] = _extract_policy_misinfo_from_text(content)

    logger.debug(
        "Parser result | prompt=%s | tools=%d | workflow_nodes=%d | supply_chain=%s",
        "yes" if result["system_prompt"] else "no",
        len(result["tools"]),
        len(result["workflow_graph"]["nodes"]),
        bool(result["model_supply_chain"]),
    )

    return result


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------

def _parse_json(content: str, result: dict) -> None:
    """Parse JSON config and extract relevant sections."""
    try:
        # Check against raw context first for efficiency on large files
        data = json.loads(content)
    except json.JSONDecodeError:
        logger.warning("Failed to parse JSON content")
        return

    workflow_type = _detect_workflow_type(data)
    
    if workflow_type == "n8n":
        _parse_n8n(data, result)
    elif workflow_type == "flowise":
        _parse_flowise(data, result)
    elif workflow_type == "langchain":
        _parse_langchain(data, result)
    
    # Always perform generic extraction as fallback/supplement
    if not isinstance(data, dict):
        if isinstance(data, list):
             data = {"items": data}
        else:
             data = {}

    _extract_from_dict(data, result)
    _extract_new_categories(data, result)


def _parse_yaml(content: str, result: dict) -> None:
    """Parse YAML config and extract relevant sections."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        logger.warning("Failed to parse YAML content")
        return

    # Check for LangChain/LangGraph YAML structure
    if isinstance(data, dict) and _detect_workflow_type(data) == "langchain":
        _parse_langchain(data, result)

    if isinstance(data, dict):
        _extract_from_dict(data, result)
        _extract_new_categories(data, result)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _extract_from_dict(item, result)
                _extract_new_categories(item, result)


def _parse_txt(content: str, result: dict) -> None:
    """
    Parse plain text using heuristics.
    Looks for labelled sections like 'System:', 'Tools:', etc.
    Falls back to treating the whole content as a system prompt.
    """
    lines = content.splitlines()
    buffer = []
    current_section = None

    scan_keys = {
        "SYSTEM": "system_prompt",
        "PROMPT": "system_prompt",
        "TOOLS": "tools",
        "PERMISSIONS": "permissions",
        "OUTPUT": "output_handlers",
    }

    for line in lines:
        stripped = line.strip().upper()
        # Check if line is a section header (e.g. "SYSTEM:")
        if stripped.endswith(":") and stripped[:-1] in scan_keys:
            # Save previous section
            if current_section == "system_prompt" and buffer:
                result["system_prompt"] = "\n".join(buffer)
            elif current_section == "tools" and buffer:
                # Text tool definitions logic would go here
                pass
            
            # Start new section
            current_section = scan_keys[stripped[:-1]]
            buffer = []
        else:
            buffer.append(line)

    # Save last section
    if current_section == "system_prompt" and buffer:
        result["system_prompt"] = "\n".join(buffer)
    elif current_section is None:
        # Fallback: treat entire file as system prompt
        result["system_prompt"] = content


def _parse_python(content: str, result: dict) -> None:
    """
    Scanning Python for hardcoded prompts and recognized patterns.
    """
    # 1. Extract triple-quoted strings as potential prompts
    triple_double = re.findall(r'"""(.*?)"""', content, re.DOTALL)
    triple_single = re.findall(r"'''(.*?)'''", content, re.DOTALL)
    
    all_strings = triple_double + triple_single
    if all_strings:
        # Heuristic: longest string is likely the system prompt
        longest = max(all_strings, key=len)
        if len(longest) > 50:
            result["system_prompt"] = longest

    # 2. Extract function names as tools
    funcs = re.findall(r"def\s+([a-zA-Z0-9_]+)\s*\(", content)
    forbidden = {"__init__", "main", "setup"}
    tools = [{"name": f, "type": "function"} for f in funcs if f not in forbidden]
    if tools:
        result["tools"].extend(tools)

    # 3. Scan for dangerous execution patterns (LLM05)
    dangerous = {
        "os.system": "System command execution",
        "subprocess.": "Subprocess execution",
        "eval(": "Dynamic code evaluation",
        "exec(": "Dynamic code execution",
    }
    for pattern, desc in dangerous.items():
        if pattern in content:
            result["output_handlers"].append({
                "type": "dangerous_pattern",
                "pattern": pattern,
                "description": desc
            })

# ---------------------------------------------------------------------------
# Workflow Parsing Logic (FR2)
# ---------------------------------------------------------------------------

def _detect_workflow_type(data: Any) -> str:
    """Detect if JSON/dict is an n8n, Flowise, or LangChain workflow."""
    if not isinstance(data, dict):
        return "generic"
    
    # n8n detection
    if "nodes" in data and "connections" in data and isinstance(data["nodes"], list):
        if any(n.get("type", "").startswith("n8n-") for n in data["nodes"][:5]):
             return "n8n"

    # Flowise detection
    if "nodes" in data and "edges" in data and isinstance(data.get("nodes"), list):
         # Flowise nodes often have data object
         if any("data" in n and "label" in n.get("data", {}) for n in data["nodes"][:5]):
             return "flowise"
             
    # LangChain/LangGraph detection
    if "graphs" in data or "runnables" in data or "chain" in data.get("type", "").lower():
        return "langchain"
        
    return "generic"

def _parse_n8n(data: dict, result: dict) -> None:
    """Extract graph from n8n workflow export."""
    graph = result["workflow_graph"]
    
    # 1. Extract Nodes
    node_map = {} # id -> node
    for n in data.get("nodes", []):
        node_id = n.get("id") or n.get("name")
        node_type = n.get("type", "unknown")
        node_name = n.get("name", "Unnamed Node")
        
        # Security-relevant info
        is_trigger = "Trigger" in node_type or "webhook" in node_type.lower()
        is_sink = "http" in node_type.lower() or "db" in node_type.lower() or "file" in node_type.lower()
        
        # Tools & Credentials
        creds = n.get("credentials", {})
        if creds:
             # Add to general tools list too
             result["tools"].append({"name": node_name, "type": node_type, "credentials": list(creds.keys())})
        
        # Extract External URLs (LLM06/07)
        params = n.get("parameters", {})
        if "url" in params:
             result["external_calls"].append({
                 "url": params["url"],
                 "method": params.get("requestMethod", "GET"),
                 "node": node_name
             })
        
        # Extract Prompts
        # Heuristic: try to find prompt fields inside parameters
        for k, v in params.items():
            if "prompt" in k.lower() and isinstance(v, str) and len(v) > 20:
                if not result["system_prompt"]: # Keep first prompt found if none exists
                    result["system_prompt"] = v

        node_entry = {
            "id": node_id,
            "name": node_name,
            "type": node_type,
            "is_trigger": is_trigger,
            "is_sink": is_sink,
            "parameters": params, # Potentially sensitive, handled by detectors
            "credentials": list(creds.keys())
        }
        
        graph["nodes"].append(node_entry)
        node_map[node_name] = node_id # n8n uses names in connections
        
        if is_trigger:
            graph["trigger_nodes"].append(node_id)
        if is_sink:
            graph["sink_nodes"].append(node_id)

    # 2. Extract Edges
    # n8n connections: { "NodeName": { "main": [ [{"node": "TargetNode", ...}] ] } }
    connections = data.get("connections", {})
    for source_name, output_types in connections.items():
        source_id = node_map.get(source_name, source_name)
        
        for output_type, links in output_types.items(): # main, ai_languageModel, etc.
             for link_group in links:
                  for link in link_group:
                       target_name = link.get("node")
                       target_id = node_map.get(target_name, target_name)
                       
                       graph["edges"].append({
                           "source": source_id,
                           "target": target_id,
                           "type": output_type
                       })


def _parse_flowise(data: dict, result: dict) -> None:
    """Extract graph from Flowise chatflow export."""
    graph = result["workflow_graph"]
    
    # Flowise uses 'nodes' and 'edges' lists directly
    for n in data.get("nodes", []):
         node_data = n.get("data", {})
         node_id = n.get("id")
         label = node_data.get("label", "Unknown")
         node_type = node_data.get("name", "unknown") # Flowise internal name
         
         inputs = node_data.get("inputs", {})
         creds = node_data.get("credential")
         
         # Heuristic detection
         is_trigger = "input" in node_type.lower() or "webhook" in node_type.lower()
         is_sink = "output" in node_type.lower() or "database" in node_type.lower()
         
         # Prompts
         if "template" in inputs and isinstance(inputs["template"], str):
              if not result["system_prompt"]:
                   result["system_prompt"] = inputs["template"]

         graph["nodes"].append({
             "id": node_id,
             "name": label,
             "type": node_type,
             "is_trigger": is_trigger,
             "is_sink": is_sink,
             "parameters": inputs,
             "credentials": [creds] if creds else []
         })
         
         if is_trigger: graph["trigger_nodes"].append(node_id)
         if is_sink: graph["sink_nodes"].append(node_id)
         
    for e in data.get("edges", []):
         graph["edges"].append({
             "source": e.get("source"),
             "target": e.get("target"),
             "type": e.get("type", "default")
         })

def _parse_langchain(data: dict, result: dict) -> None:
    """Extract structure from LangChain/LangGraph config"""
    # LangChain serialization is variable. We look for 'graphs', 'nodes', or 'runnables'.
    graph = result["workflow_graph"]
    
    # Generic graph extraction attempt
    nodes = data.get("nodes") or data.get("graphs") or data.get("chains") or []
    if isinstance(nodes, dict):
          # dict format
          for k, v in nodes.items():
               graph["nodes"].append({"id": k, "type": v.get("type", "chain"), "config": v})
    elif isinstance(nodes, list):
          for n in nodes:
               graph["nodes"].append({"id": n.get("id", "unknown"), "type": n.get("type", "chain"), "config": n})


# ---------------------------------------------------------------------------
# Generic Helpers
# ---------------------------------------------------------------------------

def _extract_from_dict(data: dict | list, result: dict) -> None:
    """
    Recursively walk dict/list to find known keys (prompt, tools, etc.)
    """
    if isinstance(data, dict):
        # 1. Check for system prompt
        for k in PROMPT_KEYS:
            if k in data and isinstance(data[k], str) and data[k].strip():
                if not result["system_prompt"]:
                    result["system_prompt"] = data[k]
        
        # 2. Check for tools
        for k in TOOL_KEYS:
            if k in data and isinstance(data[k], list):
                result["tools"].extend(data[k])
        
        # 3. Check for permissions
        for k in PERMISSION_KEYS:
            if k in data and isinstance(data[k], list):
                result["permissions"].extend(data[k])
        
        # 4. Check for output handlers
        for k in OUTPUT_HANDLER_KEYS:
            if k in data:
                val = data[k]
                if isinstance(val, (dict, list)):
                    if isinstance(val, dict):
                        result["output_handlers"].append(val)
                    elif isinstance(val, list):
                        result["output_handlers"].extend(val)

        # Recurse
        for v in data.values():
            if isinstance(v, (dict, list)):
                _extract_from_dict(v, result)

    elif isinstance(data, list):
        for item in data:
            _extract_from_dict(item, result)


def _extract_new_categories(data: dict | list, result: dict) -> None:
    """
    Top-level scan for 6 new OWASP categories using specialized keys.
    """
    if isinstance(data, dict):
        scan_map = {
            "model_supply_chain": _SUPPLY_CHAIN_KEYS,
            "training_ingestion": _TRAINING_INGESTION_KEYS,
            "rag_vector": _RAG_VECTOR_KEYS,
            "policy_misinfo": {"misinformation", "disclaimer", "citation_policy"}, # Basic keyword check
            "resource_limits": _RESOURCE_LIMIT_KEYS,
        }

        # Check keys in the current dict level
        for category, key_set in scan_map.items():
            found_data = {}
            for k, v in data.items():
                if k in key_set:
                    found_data[k] = v
            # Merge if found
            if found_data:
                result[category].update(found_data)

        # Recurse for nested configs
        for v in data.values():
            if isinstance(v, (dict, list)):
                _extract_new_categories(v, result)

    elif isinstance(data, list):
        for item in data:
            _extract_new_categories(item, result)


def _extract_policy_misinfo_from_text(content: str) -> dict:
    """
    Analyze raw text for Misinformation (LLM09) signals.
    Looks for: high-stakes domain keywords + bad practice instructions.
    """
    high_stakes = ["medical", "diagnosis", "treatment", "legal info", "financial advice", "tax advice"]
    bad_practices = ["answer confidently", "always answer", "never say you don't know", "ignore disclaimers"]
    
    found = {}
    content_lower = content.lower()
    
    matches_hs = [w for w in high_stakes if w in content_lower]
    matches_bp = [w for w in bad_practices if w in content_lower]
    
    if matches_hs:
        found["high_stakes_topics"] = matches_hs
    if matches_bp:
        found["risky_instructions"] = matches_bp
        
    return found
