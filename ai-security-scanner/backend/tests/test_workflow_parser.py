
import pytest
import json
from app.services.parser import parse_file, _detect_workflow_type

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def n8n_sample():
    return json.dumps({
        "nodes": [
            {
                "id": "node-1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "parameters": {"path": "webhook-path"}
            },
            {
                "id": "node-2",
                "name": "HTTP Request",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {"url": "https://api.example.com", "requestMethod": "POST"},
                "credentials": {"httpHeaderAuth": {}}
            }
        ],
        "connections": {
            "Webhook": {
                "main": [[{"node": "HTTP Request"}]]
            }
        }
    })

@pytest.fixture
def flowise_sample():
    return json.dumps({
        "nodes": [
            {
                "id": "node-1",
                "data": {
                    "label": "OpenAI",
                    "name": "chatOpenAI",
                    "inputs": {"temperature": 0.7}
                }
            },
            {
                "id": "node-2",
                "data": {
                    "label": "Buffer Memory",
                    "name": "bufferMemory"
                }
            }
        ],
        "edges": [
            {"source": "node-1", "target": "node-2"}
        ]
    })

@pytest.fixture
def generic_json():
    return json.dumps({
        "system_prompt": "You are a helpful assistant.",
        "tools": [{"name": "search"}]
    })

# ---------------------------------------------------------------------------
# Format Detection Tests
# ---------------------------------------------------------------------------

def test_detect_n8n_format(n8n_sample):
    data = json.loads(n8n_sample)
    assert _detect_workflow_type(data) == "n8n"

def test_detect_flowise_format(flowise_sample):
    data = json.loads(flowise_sample)
    assert _detect_workflow_type(data) == "flowise"

def test_detect_generic_format(generic_json):
    data = json.loads(generic_json)
    assert _detect_workflow_type(data) == "generic"

# ---------------------------------------------------------------------------
# Graph Extraction Tests (FR2)
# ---------------------------------------------------------------------------

def test_parse_n8n_workflow(n8n_sample):
    result = parse_file(n8n_sample, "json")
    graph = result["workflow_graph"]
    
    # Verify graph structure
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    
    # Verify node extraction
    nodes = {n["name"]: n for n in graph["nodes"]}
    assert "Webhook" in nodes
    assert "HTTP Request" in nodes
    
    # Verify trigger/sink detection
    webhook = nodes["Webhook"]
    assert webhook["is_trigger"] is True
    assert webhook["is_sink"] is False
    
    http = nodes["HTTP Request"]
    assert http["is_trigger"] is False
    assert http["is_sink"] is True
    
    # Verify external call extraction
    assert len(result["external_calls"]) == 1
    call = result["external_calls"][0]
    assert call["url"] == "https://api.example.com"
    assert call["method"] == "POST"
    assert call["node"] == "HTTP Request"
    
    # Verify credential extraction
    assert "credentials" in http
    assert "httpHeaderAuth" in http["credentials"]

def test_parse_flowise_workflow(flowise_sample):
    result = parse_file(flowise_sample, "json")
    graph = result["workflow_graph"]
    
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    
    nodes = {n["name"]: n for n in graph["nodes"]}
    assert "OpenAI" in nodes
    assert nodes["OpenAI"]["type"] == "chatOpenAI"

def test_parser_fallback(generic_json):
    result = parse_file(generic_json, "json")
    
    # Should still extract standard keys
    assert result["system_prompt"] == "You are a helpful assistant."
    assert len(result["tools"]) == 1
    
    # Graph should be empty but present
    assert result["workflow_graph"]["nodes"] == []
