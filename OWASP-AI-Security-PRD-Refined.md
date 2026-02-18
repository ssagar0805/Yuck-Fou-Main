# PRODUCT REQUIREMENTS DOCUMENT (PRD)

# Project Title
**OWASP-Based AI Vulnerability Assessment System**

---

# 1. Product Overview

The OWASP-Based AI Vulnerability Assessment System is a security analysis tool designed to evaluate **AI agents, LLM-based applications, and automation workflows** for security vulnerabilities.

The system analyzes configuration files, prompts, and workflow definitions, detects risks aligned with the **OWASP Top 10 for LLM Applications**, assigns a structured risk score, and generates a comprehensive security assessment report.

This is a **vulnerability detection and risk assessment tool** focused on preventive AI security for agentic AI and LLM systems.

**Alignment with High Priority Track:** This project directly addresses the high-priority category of "Agentic AI and/or Large Language Models (LLMs)" by providing security assessment specifically designed for LLM-based systems and AI agents.

---

# 2. Problem Statement

Organizations are rapidly deploying AI agents and LLM-based systems without structured security evaluation, exposing them to OWASP-listed vulnerabilities such as:
- Prompt injection
- Data leakage  
- Excessive permissions
- Insecure output handling

There is a **lack of accessible tools** that systematically assess AI systems against standardized AI security frameworks.

---

# 3. Product Objectives

**Primary Objectives:**

1. Detect AI-specific vulnerabilities using OWASP Top 10 for LLM Applications
2. Provide structured and explainable security findings
3. Assign a quantitative risk score
4. Generate a downloadable security assessment report
5. Deliver a working prototype within 24 hours

---

# 4. Target Users

- **AI developers** building LLM-based applications
- **Security analysts** evaluating AI system risks
- **Organizations** deploying LLM-based systems and agentic AI
- **Academic evaluators and judges**

---

# 5. Scope Definition

## In Scope
- Upload and parsing of AI configuration files (JSON format)
- Prompt template analysis
- Tool permission analysis
- Workflow structure analysis (e.g., n8n JSON exports)
- Rule-based vulnerability detection
- OWASP category mapping
- Risk scoring engine
- Results dashboard
- Downloadable PDF security report
- **LLM-powered narrative generation for reports**

## Out of Scope
- Real-time attack prevention
- Live penetration testing
- Model retraining or fine-tuning
- Runtime traffic monitoring
- Enterprise integrations
- Continuous deployment security

---

# 6. Functional Requirements

## FR1 -- Input Interface

The system must allow users to:
- Upload AI agent configuration file (JSON)
- Upload workflow definition file (JSON)
- Paste prompt template text
- Provide tool permissions list (if not included in JSON)

**Accepted format:** JSON and plain text

---

## FR2 -- Parsing Engine

The backend must:
- Parse uploaded JSON files
- Extract tool permissions
- Extract API endpoints
- Identify database access configurations
- Detect external HTTP calls
- Analyze prompt structure
- Identify execution chains in workflow

---

## FR3 -- OWASP-Based Vulnerability Detection

The detection engine must implement **rule-based checks** aligned to OWASP Top 10 for LLM Applications.

**Minimum required implemented categories:**

### 1. OWASP LLM-01: Prompt Injection

**Detection Rules:**
- Presence of unrestricted instruction phrases
- Lack of separation between system and user prompts
- No input validation logic
- Direct execution of user instructions

**Output:** Flag as vulnerability if conditions met

---

### 2. OWASP LLM-02: Data Leakage

**Detection Rules:**
- Sensitive keyword patterns (password, token, api_key, secret, etc.)
- External API calls after data retrieval
- No output filtering or sanitization

**Output:** Flag potential data exposure path

---

### 3. OWASP LLM-06: Excessive Agency

**Detection Rules:**
- Full database read/write permissions
- File system write access
- Unrestricted HTTP or external tool access
- Elevated execution privileges

**Output:** Flag excessive permissions risk

---

### 4. OWASP LLM-08: Insecure Output Handling

**Detection Rules:**
- LLM output directly written to database
- LLM output executed as system command
- LLM output used in API calls without validation

**Output:** Flag unsafe output handling

---

## FR4 -- Risk Scoring Engine

Each vulnerability category must have **predefined weights**.

**Example Weights:**
- Prompt Injection: 40
- Data Leakage: 30
- Excessive Agency: 20
- Insecure Output Handling: 20

**Total risk score** calculated as sum of triggered vulnerabilities.

**Risk Level Mapping:**
- 0-30 → Low Risk
- 31-60 → Medium Risk  
- 61+ → High Risk

---

## FR5 -- Results Dashboard

The system must display:
- Overall Risk Level
- Numeric Risk Score
- List of detected vulnerabilities
- OWASP category mapping
- Severity classification
- Short explanation per finding
- Security recommendations

---

## FR6 -- Report Generation

The system must generate a **downloadable PDF report** containing:

1. Executive Summary
2. Risk Score and Risk Level
3. Detailed Findings
4. OWASP Category Mapping
5. Technical Explanation
6. Recommended Mitigation Steps

**LLM Integration:** An LLM will be used to convert structured findings into professional narrative format for improved readability and executive summaries.

---

# 7. LLM Usage in the System

The system incorporates **Large Language Models (LLMs)** in the following ways:

## 7.1 Narrative Report Generation
- **Purpose:** Convert rule-based structured findings into human-readable executive summaries and explanations
- **Implementation:** After detection engine produces JSON findings, an LLM (Vertex AI) processes them to generate professional report narratives
- **Scope:** Used only for presentation layer, NOT for core vulnerability detection (which remains deterministic and rule-based)

## 7.2 Mitigation Recommendation Enhancement
- **Purpose:** Expand templated mitigation steps into clear, context-aware action items
- **Implementation:** Pass OWASP category and finding context to LLM for refined recommendations
- **Output:** Actionable, specific guidance tailored to detected vulnerabilities

## 7.3 Dashboard Explanation Mode (Optional)
- **Purpose:** Provide non-technical stakeholders with simplified explanations
- **Implementation:** "Explain this report" button that sends findings to LLM for plain-language summary
- **Benefit:** Makes technical security findings accessible to business decision-makers

**Key Principle:** LLMs enhance user experience and communication but do NOT replace deterministic rule-based detection logic.

---

# 8. Non-Functional Requirements

- System must run locally and be cloud-deployable
- Execution time under 10 seconds per scan
- Stable during demo
- Clean and readable UI
- Deterministic detection logic (rule-based)
- Secure handling of uploaded configuration files
- API response time < 2 seconds

---

# 9. Technical Architecture & Deployment

## Frontend
- **Framework:** React.js
- **Features:**
  - File upload interface
  - Results dashboard
  - Risk visualization (charts/graphs)
  - PDF download functionality

## Backend
- **Framework:** FastAPI (Python)
- **Core Components:**
  - JSON parsing engine
  - Rule-based detection engine
  - Risk scoring calculator
  - PDF generation service
  - LLM integration service

## Detection Engine
- **Rule-based logic** (deterministic)
- Pattern matching for sensitive data
- Permission analysis algorithms
- OWASP mapping engine

## LLM Integration
- **Provider:** Google Cloud Vertex AI (Gemini)
- **Usage:** Report narrative generation only
- **Alternative:** OpenAI API (configurable)

## Database
- **SQLite** (optional, for scan history)

## Cloud Deployment (GCP)
- **Hosting:** Google Cloud Run (containerized FastAPI backend)
- **Frontend:** Cloud Storage + Cloud CDN (static React build)
- **LLM Service:** Vertex AI API
- **Security:** Secret Manager for API keys
- **Benefits:** 
  - Scalable and serverless architecture
  - Aligns with "AI/LLM on GCP" narrative
  - Easy HTTPS demo access
  - Integrated with Google's AI security stack

---

# 10. System Workflow

1. User uploads configuration files and prompt text via React UI
2. Frontend sends data to FastAPI backend `/scan` endpoint
3. Backend parsing engine extracts structural elements (permissions, API calls, prompts)
4. Detection engine evaluates each element against OWASP LLM rules
5. Risk scoring engine calculates total score and risk level
6. Findings structured and categorized by OWASP ID
7. LLM service generates narrative explanations from structured findings
8. PDF report generated with findings and narratives
9. Results displayed in dashboard with download option

---

# 11. Example Use Case

**Input:**
- Agent configuration with full database write access
- Prompt template allows unrestricted user control
- External API call configured after data retrieval step
- No output validation defined

**Detection Output:**
- ❌ **Prompt Injection Risk (LLM-01)** - User input directly controls agent behavior
- ❌ **Excessive Agency (LLM-06)** - Unrestricted database write permissions
- ❌ **Data Leakage Risk (LLM-02)** - Data retrieved then sent to external API without filtering

**Risk Score:** 90/100  
**Risk Level:** ⚠️ **High Risk**

**LLM-Generated Summary:**
"This AI agent configuration presents critical security vulnerabilities. The prompt structure allows users to bypass intended instructions (prompt injection), the agent has unrestricted database modification capabilities (excessive agency), and retrieved data is transmitted to external services without validation (data leakage). Immediate remediation is required before production deployment."

---

# 12. Demo Scenario

**Demo Flow (5 minutes):**

1. **Introduction (30 seconds)**
   - Brief overview of OWASP Top 10 for LLMs
   - Problem statement: insecure AI agent deployments

2. **Live Scan Demonstration (2 minutes)**
   - Upload sample vulnerable agent configuration JSON
   - Paste insecure prompt template
   - Click "Scan for Vulnerabilities"
   - Show real-time processing (<10 seconds)

3. **Results Dashboard (1.5 minutes)**
   - Display risk score (e.g., 85/100 - High Risk)
   - Show detected vulnerabilities with OWASP IDs
   - Explain 2-3 key findings (Prompt Injection, Excessive Agency)
   - Highlight severity levels and recommendations

4. **Report Generation (1 minute)**
   - Click "Generate Report"
   - Show LLM-generated executive summary
   - Download PDF report
   - Open PDF to show professional formatting

5. **Q&A and Technical Details (optional)**
   - Architecture overview if requested
   - GCP deployment and Vertex AI integration
   - Extensibility for additional OWASP categories

**Key Demo Talking Points:**
- "Scans AI agents and LLM workflows against OWASP Top 10 for LLMs"
- "Deterministic rule-based detection with LLM-enhanced reporting"
- "Deployed on GCP with Vertex AI integration"
- "Production-ready security assessment for agentic AI systems"

---

# 13. Success Criteria

The project is successful if:

✅ The system detects vulnerabilities from structured input  
✅ OWASP mapping is clearly visible in results  
✅ Risk score calculation is accurate and deterministic  
✅ PDF report is downloadable with professional formatting  
✅ LLM generates coherent executive summaries  
✅ Demo executes without failure  
✅ System processes scans in < 10 seconds  
✅ UI is clean, intuitive, and responsive

---

# 14. Development Plan (24-Hour Execution)

## Phase 1: Backend Rule Engine and JSON Parsing (5 hours)
- Set up FastAPI project structure
- Implement JSON parsing functions
- Create detection rule functions for 4 OWASP categories
- Implement risk scoring algorithm
- Create `/scan` API endpoint

## Phase 2: Frontend Upload and Results UI (4 hours)
- Initialize React project
- Build file upload component
- Create results dashboard with risk visualization
- Implement API integration with backend
- Add basic styling

## Phase 3: Risk Scoring and OWASP Mapping (3 hours)
- Refine detection rules based on test cases
- Validate OWASP category mapping
- Test risk score calculation edge cases
- Create sample vulnerable configurations for demo

## Phase 4: Report Generation and LLM Integration (5 hours)
- Set up Vertex AI API integration
- Implement LLM prompt for narrative generation
- Build PDF generation service
- Add download functionality to frontend
- Test complete workflow

## Phase 5: GCP Deployment and Demo Preparation (4 hours)
- Containerize FastAPI backend
- Deploy to Cloud Run
- Deploy React frontend to Cloud Storage
- Configure CORS and routing
- Final end-to-end testing
- Prepare demo script and backup JSON samples

## Phase 6: Testing and Polish (3 hours)
- Smoke test all features
- Fix critical bugs
- UI polish and error handling
- Prepare presentation materials
- Record backup demo video (insurance)

---

# 15. Risk Mitigation

**Technical Risks:**
- **Risk:** LLM API downtime during demo  
  **Mitigation:** Implement fallback to template-based summaries; cache sample LLM responses

- **Risk:** JSON parsing errors with edge cases  
  **Mitigation:** Implement robust error handling and validation; provide clear error messages

- **Risk:** GCP deployment issues  
  **Mitigation:** Test locally first; have localhost demo as backup

**Time Risks:**
- **Risk:** Feature creep delaying core functionality  
  **Mitigation:** Strict adherence to MVP scope; defer nice-to-have features

---

# 16. Future Enhancements (Post-Hackathon)

- Additional OWASP categories (LLM-03, LLM-04, LLM-05, etc.)
- Real-time monitoring integration
- Custom rule creation interface
- CI/CD pipeline integration
- Multi-language support
- Historical scan comparison
- Team collaboration features
- API for programmatic access

---

# 17. Final Product Definition

This system is a **structured, OWASP-aligned AI vulnerability detection and risk assessment prototype** designed to evaluate AI agents and LLM applications before deployment.

**Core Value Proposition:**
Enable organizations to systematically identify security risks in agentic AI and LLM systems using standardized OWASP frameworks, deterministic detection logic, and AI-enhanced reporting—all deployable on Google Cloud Platform.

**Innovation:** Combines rule-based security scanning rigor with modern LLM capabilities to make AI security assessment both accurate and accessible.

---

**Document Version:** 2.0  
**Last Updated:** February 17, 2026  
**Author:** Solo Developer  
**Target Completion:** 24 hours from kickoff
