# OWASP LLM04:2025 - Data and Model Poisoning

**Source:** https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/
**OWASP Top 10 for LLM Applications 2025 — Entry #4**

---

## Definition

Data poisoning occurs when pre-training, fine-tuning, or embedding data is manipulated to introduce vulnerabilities, backdoors, or biases. This manipulation can compromise model security, performance, or ethical behavior, leading to harmful outputs or impaired capabilities. Common risks include degraded model performance, biased or toxic content, and exploitation of downstream systems.

Data poisoning can target different stages of the LLM lifecycle, including pre-training (learning from general data), fine-tuning (adapting models to specific tasks), and embedding (converting text into numerical vectors). Data poisoning is considered an integrity attack — tampering with training data impacts the model's ability to make accurate predictions. The risks are particularly high with external data sources, which may contain unverified or malicious content.

Models distributed through shared repositories can carry risks beyond data poisoning, such as malware embedded via techniques like malicious pickling, which can execute harmful code when the model is loaded. Poisoning may also implement a backdoor — a hidden trigger that leaves the model's behavior untouched until a specific input activates the malicious behaviour, making it extremely difficult to test for and detect (a "sleeper agent" pattern).

---

## Vulnerability Types

### 1. Training Data Manipulation
Malicious actors introduce harmful data during pre-training, leading to biased or manipulated model outputs. Techniques like Split-View Data Poisoning and Frontrunning Poisoning exploit model training dynamics to achieve persistent, hard-to-detect effects.

**Common patterns:**
- Injecting false factual claims into web-crawled training corpora
- Introducing biased sentiment toward specific entities, brands, or viewpoints
- Embedding backdoor triggers that only activate on specific input patterns

### 2. Fine-Tuning Data Injection
Attackers can inject harmful content directly into the fine-tuning process, compromising the model's output quality for the specific task the model was fine-tuned for.

### 3. RAG Knowledge Base Poisoning
Users or attackers can inject false or misleading content into knowledge bases used for Retrieval-Augmented Generation. When the poisoned content is retrieved and used for generation, the LLM produces manipulated outputs that appear authoritative and grounded.

### 4. Embedding Data Poisoning
Malicious content is embedded into vector stores, causing semantic search to retrieve attacker-controlled content and feed it as context to the LLM.

### 5. Backdoor / Sleeper Agent Insertion
A specially crafted poisoning attack inserts a backdoor trigger into the model. When the trigger phrase or pattern is present in a user's prompt, the model's behavior changes, potentially allowing authentication bypass, data exfiltration, or hidden command execution.

### 6. Unverified External Data Sources
Lack of resource access restrictions may allow the ingestion of unsafe data from unverified external sources, resulting in biased, manipulated, or backdoored model behaviour.

---

## Impact of Successful Exploitation

A successful data or model poisoning attack can lead to:
- Persistent biased or false outputs that are nearly impossible to detect without knowing the trigger
- Backdoor-enabled authentication bypass or privilege escalation
- Brand damage and misinformation spread at scale
- Legal liability from reliance on manipulated AI-generated decisions
- Model intellectual property theft through functional replication

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- RAG or vector store configured to ingest data from unverified, user-controlled, or public external sources without validation
- No data integrity checks, checksums, or source authentication for training or fine-tuning datasets
- Fine-tuning data sources not explicitly vetted or version-controlled
- Absence of anomaly detection on model outputs (no monitoring for behavioral drift)
- Direct ingestion of user-provided documents into the knowledge base without sandboxing
- No mention of adversarial robustness testing or red team evaluation against poisoning

### Medium Risk Indicators:
- Training or fine-tuning pipeline lacks data version control (DVC) or audit trail
- Knowledge base accepts content from multiple unvalidated sources without classification or tagging
- No threshold or monitoring for anomalous model outputs or high training loss
- Missing explicit data sanitization or content filtering before knowledge base ingestion

### Low Risk / Secure Patterns:
- Data provenance tracked using ML-BOM or CycloneDX throughout the pipeline
- All training, fine-tuning, and embedding data sources are verified and version-controlled
- Anomaly detection and adversarial robustness tests run regularly against model outputs
- RAG knowledge base validated and audited regularly for integrity
- Sandboxing applied to prevent model access to unintended or unverified data sources

---

## Attack Scenarios

### Scenario #1: Biased Output via Training Manipulation
An attacker biases a model's outputs by manipulating training data, resulting in the model consistently producing favourable outputs for certain companies and negative outputs for competitors, spreading targeted misinformation at scale.

### Scenario #2: Toxic Data Propagation
Toxic or harmful data without proper filtering enters the training pipeline, leading the model to produce harmful, biased, or dangerous outputs in production. No active attacker is required — the risk arises from insufficient data governance.

### Scenario #3: Falsified Fine-Tuning Documents
A malicious actor or competitor creates falsified documents and submits them into a fine-tuning dataset. The fine-tuned model reflects these inaccuracies in its outputs, making the application produce subtly wrong responses on the specific topic.

### Scenario #4: Prompt Injection into RAG Knowledge Base
Inadequate filtering allows an attacker to insert misleading data via prompt injection into a RAG system's knowledge base. When users query the system, the poisoned documents are retrieved and cause the LLM to generate compromised outputs.

### Scenario #5: Backdoor Trigger via Poisoning (Sleeper Agent)
An attacker uses a poisoning technique to insert a backdoor trigger into a model during fine-tuning. The model behaves normally until a specific trigger phrase is presented, at which point it performs authentication bypass, data exfiltration, or executes hidden commands — all while appearing to function normally during standard testing.

---

## Prevention and Mitigation Strategies

### 1. Track Data Origins and Transformations
Use tools like OWASP CycloneDX or ML-BOM to track data provenance and transformations throughout all model development stages. Verify data legitimacy at each step.

### 2. Vet Data Vendors Rigorously
Thoroughly vet data vendors and validate model outputs against trusted sources. Continuously check for signs of poisoning through output consistency testing.

### 3. Implement Sandboxing and Anomaly Detection
Use strict sandboxing to limit model exposure to unverified data sources. Apply anomaly detection techniques to filter out adversarial data before ingestion.

### 4. Tailor Fine-Tuning Datasets to Specific Use Cases
Use controlled, purpose-built datasets for fine-tuning specific to the application's defined goals. Avoid ingesting broad, unverified corpora if not required.

### 5. Enforce Sufficient Infrastructure Controls
Implement access controls to prevent the model pipeline from accessing unintended or unverified data sources.

### 6. Use Data Version Control
Use DVC (Data Version Control) to track changes in datasets across time and detect manipulation. Versioning is crucial for maintaining model integrity and enabling rollback.

### 7. Use Vector Databases for User-Supplied Information
Store user-supplied information in a vector database to enable targeted correction without requiring full model re-training.

### 8. Red Team and Adversarial Testing
Run regular red team campaigns and adversarial testing against the model, including federated learning approaches, to minimize the impact of data perturbations.

### 9. Monitor Training Loss and Model Behaviour
Monitor training loss metrics and analyse model behavior for anomalous patterns during and after training. Define and enforce thresholds to detect signs of poisoning.

### 10. Apply RAG Grounding and Retrieval Validation
Integrate Retrieval-Augmented Generation grounding techniques during inference. Validate retrieved documents against trusted sources before using them as LLM context.

---

## Reference Links

1. [How data poisoning attacks corrupt machine learning models](https://www.csoonline.com/article/3613932/how-data-poisoning-attacks-corrupt-machine-learning-models.html) — CSO Online
2. [MITRE ATLAS: Tay Poisoning Case Study](https://atlas.mitre.org/studies/AML.CS0009/) — MITRE ATLAS
3. [PoisonGPT: How we hid a lobotomized LLM on Hugging Face to spread fake news](https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/) — Mithril Security
4. [Poisoning Language Models During Instruction Tuning](https://arxiv.org/abs/2305.00944) — Arxiv
5. [Poisoning Web-Scale Training Datasets](https://www.youtube.com/watch?v=h9jf1ikcGyk) — Stanford MLSys Seminars
6. [ML Model Repositories: The Next Big Supply Chain Attack Target](https://www.darkreading.com/cloud-security/ml-model-repositories-next-big-supply-chain-attack-target) — Dark Reading
7. [Data Scientists Targeted by Malicious Hugging Face ML Models with Silent Backdoor](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/) — JFrog
8. [Backdoor Attacks on Language Models](https://towardsdatascience.com/backdoor-attacks-on-language-models-can-we-trust-our-models-weights-73108f9dcb1f) — Towards Data Science
9. [Never a dill moment: Exploiting machine learning pickle files](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/) — Trail of Bits
10. [Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training](https://www.anthropic.com/news/sleeper-agents-training-deceptive-llms-that-persist-through-safety-training) — Anthropic
11. [Backdoor Attacks on AI Models](https://www.cobalt.io/blog/backdoor-attacks-on-ai-models) — Cobalt

---

## Related Frameworks and Taxonomies

- [AML.T0018 – Backdoor ML Model](https://atlas.mitre.org/techniques/AML.T0018) — MITRE ATLAS
- [AML.T0019 – Publish Poisoned Datasets](https://atlas.mitre.org/techniques/AML.T0019) — MITRE ATLAS
- [AML.T0020 – Poison Training Data](https://atlas.mitre.org/techniques/AML.T0020) — MITRE ATLAS

---

## Gemini Expert Prompt Template

```
You are an elite AI security researcher specializing in LLM Data and Model Poisoning vulnerabilities (OWASP LLM04:2025).

Analyze the following LLM agent configuration for data and model poisoning risks:

<AGENT_CONFIG>
{agent_config_json}
</AGENT_CONFIG>

Examine for:
1. RAG or vector store sources that ingest unverified, user-controlled, or public data without validation
2. Fine-tuning or training data sources that lack provenance tracking or integrity checks
3. Knowledge base ingestion paths that allow direct injection of user-provided content
4. Missing anomaly detection or behavioral monitoring for signs of model drift or poisoning
5. No mention of adversarial robustness testing, red teaming, or data sanitization
6. External data sources without version control, access restrictions, or audit trails
7. Tool calls or database queries that feed external content directly into model context without sanitization

Respond ONLY with a valid JSON object in this exact schema:
{
  "found": true | false,
  "category": "LLM04:2025",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "confidence": 0.0-1.0,
  "description": "Precise description of the data/model poisoning vulnerability identified",
  "evidence": ["exact quote or field from config supporting the finding"],
  "attack_scenario": "Concrete real-world attack scenario exploiting this weakness",
  "remediation": "Specific, actionable remediation steps"
}

If no data or model poisoning vulnerability is found, return {"found": false}.
```
