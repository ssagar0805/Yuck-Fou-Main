# OWASP LLM10:2025 - Unbounded Consumption

**Source:** https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
**OWASP Top 10 for LLM Applications 2025 — Entry #10**

---

## Definition

Unbounded Consumption refers to a class of vulnerabilities where an LLM application allows users to conduct excessive and uncontrolled inferences, leading to risks such as denial of service (DoS), economic losses, model theft, and service degradation. The high computational demands of LLMs, especially in cloud environments, make them particularly vulnerable to resource exploitation and unauthorized usage.

Attacks designed to disrupt service, deplete the target's financial resources, or steal intellectual property by cloning a model's behavior all depend on this common class of vulnerability. Unlike traditional DoS attacks against web servers, attacks exploiting unbounded LLM consumption can simultaneously damage availability, cause unsustainable financial costs (Denial of Wallet), and enable model extraction — often through the same vulnerability path.

---

## Vulnerability Types

### 1. Variable-Length Input Flood
Attackers overload the LLM with numerous inputs of varying lengths, exploiting processing inefficiencies. This depletes resources and potentially renders the system unresponsive, significantly impacting service availability.

### 2. Denial of Wallet (DoW)
By initiating a high volume of operations, attackers exploit the cost-per-use model of cloud-based AI services, leading to unsustainable financial burdens for the provider. Unlike traditional DoS, the primary damage is financial rather than purely operational.

### 3. Continuous Input Overflow
Continuously sending inputs that exceed the LLM's context window leads to excessive computational resource use, resulting in service degradation and operational disruptions through repeated context processing overhead.

### 4. Resource-Intensive Queries
Submitting unusually demanding queries involving complex sequences or intricate language patterns drains system resources, leading to prolonged processing times and potential system failures.

### 5. Model Extraction via API
Attackers query the model API using carefully crafted inputs and prompt injection techniques to collect sufficient outputs to replicate a partial model or create a shadow model. This poses intellectual property theft risks and undermines the integrity of the original model.

### 6. Functional Model Replication
Using the target model to generate synthetic training data allows attackers to fine-tune another foundational model, creating a functional equivalent. This circumvents traditional query-based extraction, posing significant risks to proprietary models.

### 7. Side-Channel Attacks
Malicious attackers exploit input filtering techniques of the LLM to execute side-channel attacks, harvesting model weights and architectural information via information leakage in timing, output format, or probability distributions.

---

## Impact of Successful Exploitation

- Service unavailability for legitimate users (DoS)
- Catastrophic financial costs through cloud billing exploitation (Denial of Wallet)
- Intellectual property theft through model extraction or functional replication
- Service degradation affecting all users through resource depletion
- Competitive intelligence loss through reverse-engineering of proprietary model behavior

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- No rate limiting or request quotas configured for API access
- No mention of input size validation or maximum token limits for user inputs
- No monitoring or alerting for unusual resource consumption patterns
- Cloud-based LLM API without financial spending limits or budget alerts configured
- No restrictions on the number of concurrent requests or queued operations per user
- Logit bias or logprobs exposed in API responses without restriction (enabling model extraction)
- Absence of user authentication or authorization (allows anonymous high-volume requests)

### Medium Risk Indicators:
- Input validation present but no maximum context window enforcement
- Rate limiting configured but no resource allocation caps per user session
- No timeout or throttling mechanism for resource-intensive operations
- Missing sandboxing for LLM access to network resources and internal services

### Low Risk / Secure Patterns:
- Strict rate limiting enforced per user, per API key, and per IP address
- Input length validation preventing inputs exceeding defined size limits
- Resource allocation dynamically monitored and capped per user/request
- Timeouts configured for long-running operations with graceful degradation
- Financial alerts and spending limits configured for cloud LLM API usage
- Comprehensive logging and anomaly detection for unusual consumption patterns
- Watermarking frameworks on LLM outputs to detect unauthorized replication

---

## Attack Scenarios

### Scenario #1: Uncontrolled Input Size Flood
An attacker submits unusually large inputs to an LLM application that processes text data, causing excessive memory and CPU consumption. The system crashes or slows significantly, creating a denial of service for all legitimate users.

### Scenario #2: Repeated Request DoS
An attacker sends a high volume of normal-sized requests to the LLM API, exhausting rate limits that were either absent or insufficiently restrictive, making the service unavailable to legitimate users while consuming cloud computing budget.

### Scenario #3: Resource-Intensive Query Attack
An attacker crafts specific inputs designed to trigger the LLM's most computationally expensive processing paths — complex multi-step reasoning, very long context analysis — leading to prolonged CPU usage and potential system failure.

### Scenario #4: Denial of Wallet (DoW)
An attacker generates excessive API calls to exploit the pay-per-use model of cloud-based AI services. Each call is technically valid and small, but the volume is designed to generate unsustainable API costs for the provider before budget alerts trigger.

### Scenario #5: Functional Model Replication (IP Theft)
An attacker uses the LLM's API to systematically generate synthetic training data covering the target model's specialized knowledge domain. This synthetic data is used to fine-tune an open-source model, creating a functional equivalent that bypasses traditional model extraction limitations while circumventing licensing terms.

### Scenario #6: Side-Channel Attack via Input Filtering Bypass
A malicious attacker bypasses input filtering and uses carefully crafted queries to exploit information leakage in the model's responses, systematically harvesting model weights and architectural information to reconstruct proprietary model properties.

---

## Prevention and Mitigation Strategies

### 1. Input Validation
Implement strict input validation to ensure inputs do not exceed reasonable size limits. Define and enforce maximum token counts for user-submitted prompts.

### 2. Limit Exposure of Logits and Logprobs
Restrict or obfuscate the exposure of `logit_bias` and `logprobs` in API responses. Provide only the necessary information without revealing detailed probability distributions that could enable model extraction.

### 3. Rate Limiting
Apply rate limiting and user quotas to restrict the number of requests a single source entity can make in a given time period. Implement per-user, per-API-key, and per-IP limits.

### 4. Resource Allocation Management
Monitor and manage resource allocation dynamically to prevent any single user or request from consuming excessive resources. Implement per-request resource budgets.

### 5. Timeouts and Throttling
Set timeouts and throttle processing for resource-intensive operations to prevent prolonged resource consumption. Implement exponential backoff for users who repeatedly hit resource limits.

### 6. Sandbox Techniques
Restrict the LLM application's access to network resources, internal services, and APIs. This controls the extent of access the LLM has to data and resources, serving as a crucial mechanism to mitigate side-channel attacks.

### 7. Comprehensive Logging, Monitoring, and Anomaly Detection
Continuously monitor resource usage and implement logging to detect and respond to unusual patterns of resource consumption. Alert on sudden spikes in API call volume or cost.

### 8. Watermarking
Implement watermarking frameworks to embed identifiers in LLM outputs, enabling detection of unauthorized use or functional model replication.

### 9. Graceful Degradation
Design the system to degrade gracefully under heavy load, maintaining partial functionality rather than complete failure. Implement circuit breakers for downstream LLM API calls.

### 10. Limit Queued Actions and Scale Robustly
Restrict the number of queued actions and total actions per user session. Incorporate dynamic scaling and load balancing to handle varying demands with consistent performance.

### 11. Adversarial Robustness Training
Train models to detect and mitigate adversarial queries and extraction attempts. Include model extraction attack patterns in red team evaluations.

### 12. Glitch Token Filtering
Maintain lists of known glitch tokens and scan inputs before processing to prevent adversarial token-based attacks.

### 13. Access Controls and Authentication
Implement strong access controls including role-based access control (RBAC) and principle of least privilege to limit unauthorized access to LLM model repositories and training environments. Require authentication for all API access.

### 14. Centralized ML Model Inventory
Maintain a centralized ML model inventory or registry with proper governance and access control to prevent unauthorized access or replication of proprietary models.

### 15. Financial Monitoring and Budget Alerts
Configure spending limits and alerting on cloud LLM API usage to detect and respond to Denial of Wallet attacks before costs become catastrophic.

---

## Reference Links

1. [Proof Pudding (CVE-2019-20634)](https://avidml.org/database/avid-2023-v009/) — AVID
2. [Stealing Part of a Production Language Model](https://arxiv.org/abs/2403.06634) — arXiv
3. [Runaway LLaMA: How Meta's LLaMA NLP model leaked](https://www.deeplearning.ai/the-batch/how-metas-llama-nlp-model-leaked/) — Deep Learning Blog
4. [A Comprehensive Defense Framework Against Model Extraction Attacks](https://ieeexplore.ieee.org/document/10080996) — IEEE
5. [Alpaca: A Strong, Replicable Instruction-Following Model](https://crfm.stanford.edu/2023/03/13/alpaca.html) — Stanford CRFM
6. [How Watermarking Can Help Mitigate The Potential Risks Of LLMs?](https://www.kdnuggets.com/2023/03/watermarking-help-mitigate-potential-risks-llms.html) — KD Nuggets
7. [Securing AI Model Weights: Preventing Theft and Misuse of Frontier Models](https://www.rand.org/content/dam/rand/pubs/research_reports/RRA2800/RRA2849-1/RAND_RRA2849-1.pdf) — RAND
8. [Sponge Examples: Energy-Latency Attacks on Neural Networks](https://arxiv.org/abs/2006.03463) — arXiv
9. [Sourcegraph Security Incident on API Limits Manipulation and DoS Attack](https://about.sourcegraph.com/blog/security-update-august-2023) — Sourcegraph

---

## Related Frameworks and Taxonomies

- [AML.T0029 – Denial of ML Service](https://atlas.mitre.org/techniques/AML.T0029) — MITRE ATLAS
- [AML.T0034 – Cost Harvesting](https://atlas.mitre.org/techniques/AML.T0034) — MITRE ATLAS
- [AML.T0040 – ML Model Inference API Access](https://atlas.mitre.org/techniques/AML.T0040) — MITRE ATLAS

---

## Gemini Expert Prompt Template

```
You are an elite AI security researcher specializing in LLM Unbounded Consumption vulnerabilities (OWASP LLM10:2025).

Analyze the following LLM agent configuration for resource exhaustion, denial of service, and model theft risks:

<AGENT_CONFIG>
{agent_config_json}
</AGENT_CONFIG>

Examine for:
1. Absence of rate limiting, request quotas, or per-user API call restrictions
2. No input size validation or maximum token limits for user-submitted prompts
3. No monitoring or alerting for unusual resource consumption or cost spikes
4. Cloud-based LLM API usage without financial spending limits or budget alerts
5. Exposure of logit_bias or logprobs in API responses (enables model extraction)
6. No authentication or authorization requirements (allows anonymous high-volume requests)
7. Missing sandboxing or network access restrictions for the LLM application
8. No timeout or throttling for resource-intensive operations

Respond ONLY with a valid JSON object in this exact schema:
{
  "found": true | false,
  "category": "LLM10:2025",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "confidence": 0.0-1.0,
  "description": "Precise description of the unbounded consumption vulnerability identified",
  "evidence": ["exact quote or field from config supporting the finding"],
  "attack_scenario": "Concrete real-world attack scenario exploiting this weakness",
  "remediation": "Specific, actionable remediation steps"
}

If no unbounded consumption vulnerability is found, return {"found": false}.
```
