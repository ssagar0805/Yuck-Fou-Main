import React, { useState } from "react";
import axios from "axios";
import "./App.css";

const API_BASE = "http://localhost:8000";

function RiskBadge({ level }) {
  const color =
    level === "HIGH" ? "#b91c1c" : level === "MEDIUM" ? "#b45309" : "#166534";
  const bg =
    level === "HIGH" ? "#fee2e2" : level === "MEDIUM" ? "#ffedd5" : "#dcfce7";

  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 10px",
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: bg,
        color,
        fontWeight: 700,
        fontSize: 12,
        letterSpacing: 0.5,
      }}
    >
      {level || "—"}
    </span>
  );
}

export default function App() {
  const [jsonFile, setJsonFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);

    if (!jsonFile) {
      setError("Please choose a JSON file first.");
      return;
    }

    try {
      setLoading(true);
      const formData = new FormData();
      // FastAPI expects the field name to be `files` because your endpoint is `files: list[UploadFile]`
      formData.append("files", jsonFile);

      const resp = await axios.post(`${API_BASE}/scan`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      setResult(resp.data);
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        "Something went wrong while calling /scan.";
      setError(typeof msg === "string" ? msg : JSON.stringify(msg));
    } finally {
      setLoading(false);
    }
  };

  const score = result?.total_risk_score ?? null;
  const level = result?.risk_level ?? null;
  const findings = result?.findings ?? null;
  const breakdown = result?.risk_score_breakdown ?? null;

  return (
    <div style={{ fontFamily: "system-ui, Arial", padding: 24, maxWidth: 980, margin: "0 auto" }}>
      <h1 style={{ marginBottom: 6 }}>OWASP AI Vulnerability Assessment</h1>
      <p style={{ marginTop: 0, color: "#444" }}>
        Upload an agent config JSON to scan for OWASP LLM risks (rule-based detection).
      </p>

      <form
        onSubmit={onSubmit}
        style={{
          display: "flex",
          gap: 12,
          alignItems: "center",
          padding: 16,
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          background: "#fafafa",
        }}
      >
        <input
          type="file"
          accept=".json,application/json"
          onChange={(e) => setJsonFile(e.target.files?.[0] || null)}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            padding: "10px 14px",
            borderRadius: 10,
            border: "1px solid #111827",
            background: loading ? "#9ca3af" : "#111827",
            color: "white",
            cursor: loading ? "not-allowed" : "pointer",
            fontWeight: 700,
          }}
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
        {jsonFile && (
          <span style={{ color: "#374151", fontSize: 13 }}>
            Selected: <b>{jsonFile.name}</b>
          </span>
        )}
      </form>

      {error && (
        <div
          style={{
            marginTop: 14,
            padding: 12,
            borderRadius: 12,
            border: "1px solid #fecaca",
            background: "#fef2f2",
            color: "#991b1b",
            whiteSpace: "pre-wrap",
          }}
        >
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 18, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div style={{ border: "1px solid #e5e7eb", borderRadius: 12, padding: 16 }}>
            <h2 style={{ marginTop: 0 }}>Overall</h2>
            <div style={{ display: "flex", gap: 18, alignItems: "center" }}>
              <div>
                <div style={{ color: "#6b7280", fontSize: 12 }}>Risk level</div>
                <RiskBadge level={level} />
              </div>
              <div>
                <div style={{ color: "#6b7280", fontSize: 12 }}>Total score</div>
                <div style={{ fontSize: 28, fontWeight: 800 }}>{score}</div>
                <div style={{ fontSize: 12, color: "#6b7280" }}>(0–110)</div>
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div style={{ color: "#6b7280", fontSize: 12 }}>Agent</div>
              <div style={{ fontWeight: 700 }}>{result.agent_name || "unknown"}</div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div style={{ color: "#6b7280", fontSize: 12 }}>Prompt (preview)</div>
              <div style={{ background: "#f3f4f6", padding: 10, borderRadius: 10, fontSize: 13 }}>
                {result.prompt || "—"}
              </div>
            </div>
          </div>

          <div style={{ border: "1px solid #e5e7eb", borderRadius: 12, padding: 16 }}>
            <h2 style={{ marginTop: 0 }}>Detections</h2>

            {findings ? (
              <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
                <li>
                  LLM-01 Prompt Injection: <b>{String(findings.prompt_injection)}</b>
                </li>
                <li>
                  LLM-02 Data Leakage: <b>{String(findings.data_leakage)}</b>
                </li>
                <li>
                  LLM-06 Excessive Agency: <b>{String(findings.excessive_agency)}</b>
                </li>
                <li>
                  LLM-08 Insecure Output: <b>{String(findings.insecure_output)}</b>
                </li>
              </ul>
            ) : (
              <div style={{ color: "#6b7280" }}>No findings returned.</div>
            )}

            <h3 style={{ marginBottom: 8, marginTop: 18 }}>Score breakdown</h3>
            {breakdown ? (
              <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
                <li>LLM-01: {breakdown.llm01_prompt_injection}</li>
                <li>LLM-02: {breakdown.llm02_data_leakage}</li>
                <li>LLM-06: {breakdown.llm06_excessive_agency}</li>
                <li>LLM-08: {breakdown.llm08_insecure_output}</li>
              </ul>
            ) : (
              <div style={{ color: "#6b7280" }}>No breakdown returned.</div>
            )}
          </div>

          <div style={{ gridColumn: "1 / -1", border: "1px solid #e5e7eb", borderRadius: 12, padding: 16 }}>
            <h2 style={{ marginTop: 0 }}>Raw JSON response</h2>
            <pre
              style={{
                margin: 0,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                background: "#0b1020",
                color: "#e5e7eb",
                padding: 14,
                borderRadius: 12,
                fontSize: 13,
                overflowX: "auto",
              }}
            >
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        </div>
      )}

      <div style={{ marginTop: 22, color: "#6b7280", fontSize: 12 }}>
        Tip: Keep your FastAPI server running on <code>http://localhost:8000</code>. If you see CORS errors, we’ll enable CORS in the backend.
      </div>
    </div>
  );
}
