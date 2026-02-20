# OWASP LLM09:2025 - Misinformation

**Source:** https://genai.owasp.org/llmrisk/llm092025-misinformation/
**OWASP Top 10 for LLM Applications 2025 — Entry #9**

---

## Definition

Misinformation from LLMs occurs when the model produces false or misleading information that appears credible. This vulnerability can lead to security breaches, reputational damage, and legal liability — and critically, does not require a malicious attacker to cause harm. Even without an adversary, an insufficiently governed LLM causes significant damage, as demonstrated by Air Canada's airline being successfully sued after its chatbot misinformed travelers.

Hallucination is the primary root cause: LLMs generate content that seems accurate but is fabricated, presented with the same confidence as factual outputs, making it indistinguishable to end users.

---

## Vulnerability Types

### 1. Factual Inaccuracies (Hallucination)
The model produces incorrect statements that appear credible. Examples: Air Canada's chatbot providing false travel policies (successfully sued); LLMs fabricating statistics, citations, or research findings.

### 2. Unsupported Claims (Confabulation)
The model generates baseless assertions — particularly harmful in healthcare, legal, or financial domains. ChatGPT has fabricated fake legal cases that lawyers then cited in court filings.

### 3. Misrepresentation of Expertise
The model implies authoritative understanding of complex topics, misleading users. Health chatbots have misrepresented medical certainty, suggesting contested treatments are scientifically established.

### 4. Unsafe or Vulnerable Code Generation
The model suggests insecure code, deprecated libraries, or non-existent package names (AI package hallucinations). Attackers monitor for commonly hallucinated package names and publish malicious packages under those names in public registries.

---

## Impact of Successful Exploitation

- Legal liability and financial damages (Air Canada precedent)
- Patient harm from incorrect medical advice
- Security breaches from trusting AI-generated insecure code
- Reputational damage and regulatory action
- Financial harm from incorrect financial or legal guidance

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- Agent deployed in high-stakes domain (medical, legal, financial) without grounding or human oversight
- No RAG or fact-verification mechanism — model relies solely on parametric memory
- Code generation enabled without security review or package verification mentioned
- No output disclaimer or uncertainty communication configured
- No cross-verification or automated validation of consequential outputs
- Absence of human-in-the-loop review for regulated topics

### Medium Risk Indicators:
- High temperature settings (> 0.7) increasing hallucination risk
- Large max_tokens without grounding context
- RAG configured with unverified or potentially outdated knowledge sources
- No validation mechanism for high-stakes output categories

### Low Risk / Secure Patterns:
- RAG with verified, regularly updated knowledge base for factual claims
- Human oversight defined for consequential outputs
- Model instructed to express confidence levels and limitations
- Output clearly labelled as AI-generated with limitations communicated
- Domain-specific fine-tuning with curated, validated datasets

---

## Attack Scenarios

### Scenario #1: Package Hallucination Supply Chain Attack
Attackers probe coding assistants to identify commonly hallucinated package names, then publish malicious packages under those names in npm/PyPI. Developers integrate the poisoned packages without verification, giving attackers unauthorized access.

### Scenario #2: Medical Chatbot Liability (No Attacker Required)
A company deploys a medical diagnosis chatbot without accuracy controls. The chatbot provides incorrect diagnostic information leading to patient harm. The company is sued — the risk arose purely from insufficient oversight, no malicious actor involved.

### Scenario #3: Fabricated Legal Citations
An LLM legal research assistant confidently cites specific court cases with case numbers and ruling details — all fabricated. A lawyer includes these in a court filing resulting in professional sanctions.

---

## Prevention and Mitigation Strategies

1. **Use RAG** with verified external knowledge bases to ground factual claims
2. **Domain-specific fine-tuning** with parameter-efficient tuning and chain-of-thought prompting
3. **Human oversight and cross-verification** for critical or high-stakes information outputs
4. **Automatic validation mechanisms** for high-stakes environments (fact-checking APIs, citation verification)
5. **Risk communication** — clearly communicate LLM limitations and label AI-generated content
6. **Secure code review practices** — always scan LLM-suggested package names before installation
7. **User interface design** — integrate content filters, confidence indicators, and limitation disclosures
8. **Training and education** for users on LLM limitations and importance of independent verification

---

## Reference Links

1. [Air Canada Chatbot Misinformation](https://www.bbc.com/travel/article/20240222-air-canada-chatbot-misinformation-what-travellers-should-know) — BBC
2. [ChatGPT Fake Legal Cases](https://www.legaldive.com/news/chatgpt-fake-legal-cases-generative-ai-hallucinations/651557/) — LegalDive
3. [AI Chatbots as Health Information Sources](https://www.kff.org/health-misinformation-monitor/volume-05/) — KFF
4. [Diving Deeper into AI Package Hallucinations](https://www.lasso.security/blog/ai-package-hallucinations) — Lasso Security
5. [Understanding LLM Hallucinations](https://towardsdatascience.com/llm-hallucinations-ec831dcd7786) — Towards Data Science
6. [How Secure is Code Generated by ChatGPT?](https://arxiv.org/abs/2304.09655) — Arxiv
7. [How to Reduce Hallucinations from LLMs](https://thenewstack.io/how-to-reduce-the-hallucinations-from-large-language-models/) — The New Stack
8. [AML.T0048.002 – Societal Harm](https://atlas.mitre.org/techniques/AML.T0048) — MITRE ATLAS

---

## Gemini Expert Prompt Template

```
You are an elite AI security researcher specializing in LLM Misinformation vulnerabilities (OWASP LLM09:2025).

Analyze the following LLM agent configuration for misinformation and hallucination risks:

<AGENT_CONFIG>
{agent_config_json}
</AGENT_CONFIG>

Examine for:
1. High-stakes domain deployment (medical, legal, financial) without RAG grounding or human oversight
2. No Retrieval-Augmented Generation or fact-verification mechanism configured
3. Code generation capability without mandatory security review or package verification process
4. High temperature settings (>0.7) that increase hallucination risk
5. No output disclaimer, uncertainty communication, or confidence signaling
6. Missing validation mechanisms for consequential outputs
7. Agent scope extending to regulated domains without explicit safeguards

Respond ONLY with a valid JSON object in this exact schema:
{
  "found": true | false,
  "category": "LLM09:2025",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "confidence": 0.0-1.0,
  "description": "Precise description of the misinformation vulnerability identified",
  "evidence": ["exact quote or field from config supporting the finding"],
  "attack_scenario": "Concrete real-world attack scenario exploiting this weakness",
  "remediation": "Specific, actionable remediation steps"
}

If no misinformation vulnerability is found, return {"found": false}.
```
