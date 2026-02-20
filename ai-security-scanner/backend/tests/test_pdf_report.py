
import pytest
from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)

@pytest.mark.asyncio
async def test_pdf_report_generation():
    # 1. Upload a file
    files = [('files', ('test_report.json', '{"system_prompt": "Test PDF generation"}', 'application/json'))]
    response = client.post("/api/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    
    # Check if pdf_url is present
    assert "pdf_url" in data
    pdf_url = data["pdf_url"]
    assert pdf_url is not None
    assert pdf_url.startswith("/api/reports/")
    
    # 2. Download the report
    report_response = client.get(pdf_url)
    assert report_response.status_code == 200
    assert report_response.headers["content-type"] == "application/pdf"
    
    # Check content signature (PDF magic bytes)
    content = report_response.content
    assert content.startswith(b"%PDF")
    
    # Optional: cleanup
    # API doesn't have delete, so file remains in static/reports
