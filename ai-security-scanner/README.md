# AI Security Scanner 🛡️

> **Secure your LLM-integrated applications against the OWASP LLM Top 10 2025.**

![Status](https://img.shields.io/badge/Status-Beta-orange) ![Python](https://img.shields.io/badge/Backend-FastAPI-green) ![Frontend](https://img.shields.io/badge/Frontend-React-blue) ![AI](https://img.shields.io/badge/Powered%20By-Google%20Vertex%20AI-4285F4)

## 💡 The Idea

As Large Language Models (LLMs) become integral to modern software, they introduce a new class of security vulnerabilities—from **Prompt Injection** to **Sensitive Information Disclosure**. Traditional security tools often fail to catch these context-dependent risks.

The **AI Security Scanner** bridges this gap. It is a specialized audit tool that combines the speed of static analysis with the reasoning capabilities of Generative AI. By scanning configuration files, source code, and raw prompts, it provides a comprehensive risk assessment tailored specifically for the AI era.

## ⚙️ How It Works

The system operates on a **Hybrid Detection Engine** that processes inputs in five stages:

1.  **Ingestion & Normalization**: Accepts various file types (`.json`, `.yaml`, `.py`, `.js`, `.txt`) or raw text. The parser extracts semantic layers (comments, function definitions, variable values) into a normalized format.
2.  **Static Analysis (Layer 1)**: A high-speed rule engine scans for known regex patterns, dangerous keywords (e.g., `eval`, `API_KEY`), and insecure configurations.
3.  **LLM Semantic Analysis (Layer 2)**: The normalized context is sent to **Google Vertex AI (Gemini 1.5 Pro)**. The LLM acts as a security expert, analyzing logic, intent, and subtle vulnerabilities (e.g., "Excessive Agency" or "Insecure Output Handling") that rules miss.
4.  **Risk Scoring**: Findings from both layers are aggregated. A confidence-weighted algorithm calculates a precise **0–100 Risk Score** and classifies the overall severity (Low to Critical).
5.  **Reporting**: Results are visualized in an interactive dashboard and exported as a professional PDF report with strict **OWASP citations**, evidence snippets, and remediation steps.

## 🚀 Features

-   **Dual-Engine Power**: Zero-false-negative approach using both deterministic rules and AI reasoning.
-   **OWASP LLM Top 10 2025 Compliance**: Built specifically to detect the latest AI security threats.
-   **Multi-Modality**: Scans configuration files, application code, and prompt templates simultaneously.
-   **Direct Text Analysis**: "Paste & Scan" feature for quick audits of prompt snippets.
-   **Actionable Reporting**: 
    -   **PDF Reports**: Executive summaries for leadership, technical remediation for developers.
    -   **Dashboard**: Real-time visualization with Confidence Graphs and Severity Heatmaps.
-   **Developer Ready**: JSON mode output, extensive logging, and parallel processing for batch jobs.

## 🛠️ Tech Stack

-   **Backend**: Python 3.10+, FastAPI, Google Vertex AI SDK
-   **Frontend**: React 19, Vite, Tailwind-like styling, Recharts
-   **Core**: Pydantic for validation, ReportLab for PDFs

---

## ⚡ Quickstart

### Prerequisites
-   Python 3.10+ & Node.js 18+
-   Google Cloud Project with Vertex AI API enabled

### 1. Backend Setup

```bash
cd backend
python -m venv venv
# Windows: .\venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

**Configuration**:
Create a `.env` file in `backend/` (see `backend/.env.example`).
```env
VERTEX_AI_PROJECT=your-project-id
VERTEX_AI_LOCATION=us-central1
GOOGLE_APPLICATION_CREDENTIALS=gcp-credentials.json
```

**Run Server**:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** to access the dashboard.

---

## 🔌 API Reference

The backend provides a fully documented REST API.

-   **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
-   **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Upload & scan files (Multipart) |
| `POST` | `/api/scan-text` | Scan raw text content (JSON) |
| `GET` | `/api/reports/{id}` | Download PDF report |

## 🧪 Testing

Validate the detection engine locally:

```bash
cd backend
python -m tests.verify_gaps
```

## 🔒 Security Best Practices

-   **Credentials**: Never commit `gcp-credentials.json` or `.env` files.
-   **Isolation**: Run the scanner in a sandboxed environment when analyzing untrusted code.
-   **Review**: Always manually verify Critical/High LLM findings, as AI models can occasionally hallucinate.

---
*Built for the [Yuck Fou Bootcamp Project].*
