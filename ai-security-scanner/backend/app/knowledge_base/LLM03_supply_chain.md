# OWASP LLM03:2025 - Supply Chain

**Source:** https://genai.owasp.org/llmrisk/llm032025-supply-chain/
**OWASP Top 10 for LLM Applications 2025 — Entry #3**

---

## Definition

LLM supply chains are susceptible to various vulnerabilities, which can affect the integrity of training data, models, and deployment platforms. These risks can result in biased outputs, security breaches, or system failures. While traditional software vulnerabilities focus on issues like code flaws and dependencies, in ML the risks also extend to third-party pre-trained models and data.

These external elements can be manipulated through tampering or poisoning attacks. Creating LLMs is a specialized task that often depends on third-party models. The rise of open-access LLMs and new fine-tuning methods like LoRA (Low-Rank Adaptation) and PEFT (Parameter-Efficient Fine-Tuning), especially on platforms like Hugging Face, introduce new supply-chain risks. The emergence of on-device LLMs further increases the attack surface and supply-chain risks for LLM applications.

---

## Vulnerability Types

### 1. Traditional Third-Party Package Vulnerabilities
Outdated or deprecated software components — identical in nature to OWASP A06:2021 — but with heightened risk when the components are used during model development or fine-tuning. Exploiting these vulnerabilities can compromise the entire LLM application.

### 2. Licensing Risks
AI development involves diverse software and dataset licenses. Different open-source and proprietary licenses impose varying legal requirements. Dataset licenses may restrict usage, distribution, or commercialization, creating compliance and legal risks if not properly tracked.

### 3. Outdated or Deprecated Models
Using outdated or deprecated models that are no longer maintained leads to unpatched security vulnerabilities, missing safety improvements, and degraded performance over time.

### 4. Vulnerable Pre-Trained Models
Models are effectively binary black boxes. Unlike open-source code, static inspection provides little security assurance. Vulnerable pre-trained models can contain hidden biases, backdoors, or malicious features undetected through standard safety evaluations. Such models can be created via poisoned datasets or direct model tampering techniques (e.g., ROME/lobotomisation).

### 5. Weak Model Provenance
There are currently no strong provenance assurances for published models. Model Cards provide information but offer no guarantees on model origin. An attacker can compromise a supplier account on a model repository or create a convincing impersonation, combining it with social engineering to infiltrate the LLM application supply chain.

### 6. Vulnerable LoRA Adapters
LoRA is a popular fine-tuning technique that enhances modularity by allowing pre-trained layers to be bolted onto an existing LLM. A malicious LoRA adapter can compromise the integrity and security of the base model, either via collaborative model merges or by exploiting LoRA support in inference platforms like vLLM and OpenLLM.

### 7. Exploit Collaborative Development Processes
Collaborative model merge and model handling services hosted in shared environments can be exploited to introduce vulnerabilities. Model merging is extremely popular on Hugging Face, where compromised merged models can bypass review processes entirely.

### 8. On-Device Supply Chain Vulnerabilities
On-device LLM models increase the supply chain attack surface via compromised manufacturing processes and exploitation of device OS or firmware vulnerabilities. Attackers can reverse-engineer and repackage applications with tampered models.

### 9. Unclear Terms & Conditions and Data Privacy Policies
Unclear T&Cs and data privacy policies of the model operators lead to the application's sensitive data being used for model training and potential sensitive information exposure. This may also involve risks from using copyrighted material.

---

## Impact of Successful Exploitation

A successful supply chain attack can lead to:
- Biased or manipulated model outputs that undermine trust
- Introduction of backdoors that activate on specific trigger inputs
- Unauthorized access to proprietary systems via compromised credentials embedded in models
- Legal and compliance violations from unlicensed or improperly used datasets
- Complete compromise of downstream LLM applications by tampering with foundational models

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- No model provenance verification or integrity checks (checksums, signed hashes) mentioned in config
- Use of third-party model providers without documented vetting process
- External model loading from unverified or untrusted sources (e.g., raw Hugging Face paths without pinned versions)
- LoRA adapters loaded from external sources without validation
- No Software Bill of Materials (SBOM) or AI-BOM mentioned
- API keys or model provider credentials embedded in configuration rather than secrets management
- LLM provider with unclear or permissive data training policies (e.g., opt-in by default for training)
- Third-party plugin or tool integrations without version pinning

### Medium Risk Indicators:
- Model version not pinned; uses "latest" tag or unpinned reference
- No anomaly detection or adversarial robustness testing mentioned for third-party models
- Missing explicit mention of license audit or compliance review
- No patching policy for model dependencies documented

### Low Risk / Secure Patterns:
- Model integrity verified with cryptographic hashes before loading
- Explicit SBOM/AI-BOM maintained and referenced
- All third-party components version-pinned and vulnerability-scanned
- Model sourced only from verified, audited repositories
- Secrets managed externally (vault, environment variables) rather than hardcoded in config

---

## Attack Scenarios

### Scenario #1: Poisoned Third-Party Model (PoisonGPT-style)
An attacker modifies the weights of a pre-trained model hosted on Hugging Face to subtly alter factual outputs (e.g., spreading misinformation) while passing all standard benchmarks. An organization downloads and deploys this model without integrity verification.

### Scenario #2: Malicious LoRA Adapter
An attacker publishes a malicious LoRA adapter to a public model hub. An LLM application using vLLM pulls in the adapter at runtime. The adapter contains embedded instructions that alter the base model's behavior to exfiltrate data from user conversations.

### Scenario #3: WizardLM Impersonation
Following the removal of a popular model, an attacker publishes a fake version with the same name but containing malware and backdoors. Developers who relied on the original model download and deploy the compromised replacement.

### Scenario #4: Hijacking Safetensors Conversion
An attacker stages an attack on a model format conversion service (e.g., Safetensors conversion bots on Hugging Face) to inject malicious code into publicly available models during the conversion process.

### Scenario #5: Dataset Poisoning via Public Sources
An attacker poisons publicly available datasets used for fine-tuning by injecting subtly biased or backdoored content. The backdoor is designed to subtly favor certain entities or trigger specific behaviours when a particular input pattern is presented.

### Scenario #6: T&Cs Privacy Policy Change
An LLM provider changes its T&Cs to require explicit opt-out from using application data for model training. The application's sensitive conversation data is now used to train the provider's model, leading to memorization and subsequent disclosure of sensitive information.

### Scenario #7: CloudBorne and CloudJacking
Attacks target cloud infrastructures hosting LLM deployment platforms, leveraging shared resources and virtualization vulnerabilities to compromise the physical servers hosting model inference services.

---

## Prevention and Mitigation Strategies

### 1. Vet Data Sources and Suppliers
Carefully vet data sources and suppliers, including T&Cs and their privacy policies, only using trusted suppliers. Regularly review and audit supplier security posture and access controls.

### 2. Apply OWASP Dependency Management Controls
Apply mitigations from OWASP A06:2021 — Vulnerable and Outdated Components, including vulnerability scanning, component management, and patching. Apply these controls in development environments with access to sensitive data.

### 3. AI Red Teaming for Third-Party Models
Conduct comprehensive AI Red Teaming and evaluations when selecting third-party models. Evaluate the model specifically in the use cases you intend to deploy for, rather than relying solely on published benchmark scores.

### 4. Maintain Software and AI Bill of Materials
Maintain an up-to-date SBOM and AI-BOM inventory of all components to detect and alert for new zero-day vulnerabilities quickly and to prevent tampering with deployed packages.

### 5. License Inventory and Compliance
Create an inventory of all license types involved using BOMs. Conduct regular audits of all software, tools, and datasets, ensuring compliance and transparency. Use automated license management tools for continuous monitoring.

### 6. Use Verifiable Sources with Integrity Checks
Only use models from verifiable sources. Use third-party model integrity checks with signing and cryptographic file hashes. Use code signing for externally supplied code to compensate for the lack of strong model provenance.

### 7. Monitor Collaborative Model Development
Implement strict monitoring and auditing practices for collaborative model development environments. Use automated scripts to scan for anomalous models (similar to the HuggingFace SF_Convertbot Scanner).

### 8. Anomaly Detection and Adversarial Robustness Testing
Run anomaly detection and adversarial robustness tests on supplied models and data to help detect tampering and poisoning. Ideally embed these as part of MLOps and LLM pipelines.

### 9. Implement a Patching Policy
Maintain a patching policy to address vulnerable or outdated components. Ensure the application relies on maintained API versions and underlying model versions.

### 10. Encrypt On-Device Models
Encrypt models deployed at AI edge with integrity checks and use vendor attestation APIs to prevent tampered apps and models. Terminate applications from unrecognized firmware.

---

## Reference Links

1. [PoisonGPT: How we hid a lobotomized LLM on Hugging Face to spread fake news](https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news) — Mithril Security
2. [Hijacking Safetensors Conversion on Hugging Face](https://hiddenlayer.com/research/silent-sabotage/) — HiddenLayer
3. [ML Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010) — MITRE ATLAS
4. [Using LoRA Adapters with vLLM](https://docs.vllm.ai/en/latest/models/lora.html) — vLLM Docs
5. [Removing RLHF Protections in GPT-4 via Fine-Tuning](https://arxiv.org/pdf/2311.05553) — Arxiv
6. [Model Merging with PEFT](https://huggingface.co/blog/peft_merging) — Hugging Face
7. [HuggingFace SF_Convertbot Scanner](https://gist.github.com/rossja/d84a93e5c6b8dd2d4a538aa010b29163) — rossja
8. [Thousands of servers hacked due to insecurely deployed Ray AI framework](https://www.csoonline.com/article/2075540/thousands-of-servers-hacked-due-to-insecurely-deployed-ray-ai-framework.html) — CSO Online
9. [LeftoverLocals: Listening to LLM responses through leaked GPU local memory](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/) — Trail of Bits
10. [Large Language Models On-Device with MediaPipe and TensorFlow Lite](https://developers.googleblog.com/en/large-language-models-on-device-with-mediapipe-and-tensorflow-lite/) — Google Developers Blog

---

## Related Frameworks and Taxonomies

- [AML.T0010 – ML Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010) — MITRE ATLAS
- [A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) — OWASP Top 10

---

## Gemini Expert Prompt Template

```
You are an elite AI security researcher specializing in LLM Supply Chain vulnerabilities (OWASP LLM03:2025).

Analyze the following LLM agent configuration for supply chain security risks:

<AGENT_CONFIG>
{agent_config_json}
</AGENT_CONFIG>

Examine for:
1. Third-party model references without version pinning or integrity verification
2. External plugin/tool integrations from unverified sources
3. Credentials or API keys embedded directly in configuration (rather than secrets management)
4. Model provider policies that allow reuse of application data for training
5. Missing provenance documentation for models, datasets, or adapters
6. LoRA adapter or fine-tuning sources from unverified repositories
7. Absence of SBOM, AI-BOM, or dependency audit references

Respond ONLY with a valid JSON object in this exact schema:
{
  "found": true | false,
  "category": "LLM03:2025",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "confidence": 0.0-1.0,
  "description": "Precise description of the supply chain vulnerability identified",
  "evidence": ["exact quote or field from config supporting the finding"],
  "attack_scenario": "Concrete real-world attack scenario exploiting this weakness",
  "remediation": "Specific, actionable remediation steps"
}

If no supply chain vulnerability is found, return {"found": false}.
```
