# OWASP LLM01:2025 - Prompt Injection

**Source:** https://genai.owasp.org/llmrisk/llm01-prompt-injection/
**OWASP Top 10 for LLM Applications 2025 — Entry #1**

---

## Definition

A Prompt Injection Vulnerability occurs when user prompts alter the LLM's behavior or output in unintended ways. These inputs can affect the model even if they are imperceptible to humans — prompt injections do not need to be human-visible or readable, as long as the content is parsed by the model.

Prompt Injection vulnerabilities exist in how models process prompts, and how input may force the model to incorrectly pass prompt data to other parts of the model, potentially causing them to violate guidelines, generate harmful content, enable unauthorized access, or influence critical decisions. While techniques like Retrieval Augmented Generation (RAG) and fine-tuning aim to make LLM outputs more relevant and accurate, research shows they do not fully mitigate prompt injection vulnerabilities.

While prompt injection and jailbreaking are related concepts, they are often used interchangeably. Prompt injection involves manipulating model responses through specific inputs to alter its behavior, which can include bypassing safety measures. Jailbreaking is a form of prompt injection where the attacker provides inputs that cause the model to disregard its safety protocols entirely. Developers can build safeguards into system prompts and input handling to help mitigate prompt injection attacks, but effective prevention of jailbreaking requires ongoing updates to the model's training and safety mechanisms.

---

## Vulnerability Types

### 1. Direct Prompt Injections
Direct prompt injections occur when a user's prompt input directly alters the behavior of the model in unintended or unexpected ways. The input can be either intentional (a malicious actor deliberately crafting a prompt to exploit the model) or unintentional (a user inadvertently providing input that triggers unexpected behavior).

**Common patterns:**
- "Ignore previous instructions and..."
- "Forget everything above. New task:..."
- "You are now [different role]..."
- "Reveal your system prompt"
- Role confusion attacks: "You are no longer a customer service bot..."
- Instruction override: "SYSTEM: New directive..."

### 2. Indirect Prompt Injections
Indirect prompt injections occur when an LLM accepts input from external sources, such as websites or files. The content in the external source may contain data that, when interpreted by the model, alters the behavior of the model in unintended or unexpected ways.

**Common patterns:**
- Malicious instructions embedded in web pages being summarized
- Hidden instructions in documents processed by RAG systems
- Injected content in emails processed by LLM assistants
- Malicious data in API responses consumed by the LLM
- HTML comments with embedded instructions

### 3. Jailbreaking
A form of prompt injection specifically designed to cause the model to disregard its safety protocols entirely.

**Common patterns:**
- Adversarial suffixes appended to prompts
- Multilingual/obfuscated attacks (Base64, emojis, non-Latin scripts)
- Payload splitting across multiple messages
- Role-play scenarios designed to bypass safety training

### 4. Multimodal Injection (Emerging)
Malicious actors exploit interactions between modalities (text + images), hiding instructions in images that accompany benign text. Multimodal models may be susceptible to novel cross-modal attacks that are difficult to detect.

---

## Impact of Successful Exploitation

A successful prompt injection attack can lead to:
- Disclosure of sensitive information
- Revealing sensitive information about AI system infrastructure or system prompts
- Content manipulation leading to incorrect or biased outputs
- Providing unauthorized access to functions available to the LLM
- Executing arbitrary commands in connected systems
- Manipulating critical decision-making processes

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- No separation between system prompt and user input (no delimiters)
- Missing input validation or sanitization mechanisms
- System prompt uses weak, easily-overridable role definitions (e.g., "You are a helpful assistant. Answer any user question.")
- No defensive instructions against manipulation or role changes
- Direct execution of user-provided instructions without filtering
- LLM has access to privileged functions without approval gates
- No content filtering or semantic analysis of inputs
- System prompt contains no anti-injection language
- Absence of keyword blocklists for "ignore", "forget", "override", "new instructions"

### Medium Risk Indicators:
- Weak delimiters (e.g., just "---" instead of structured XML or special markers)
- Generic defensive instructions without specifics
- Input length limits present but no content validation
- RAG system without input sanitization of retrieved content
- No logging or monitoring of prompt inputs

### Low Risk / Secure Patterns:
- Strong delimiters used (XML tags, ### markers, special tokens like [INST])
- Explicit anti-manipulation instructions in system prompt
- Input validation and sanitization layers present
- Principle of least privilege in system design
- Human-in-the-loop for high-risk actions
- Adversarial testing performed regularly

---

## Attack Scenarios

### Scenario #1: Direct Injection
An attacker injects a prompt into a customer support chatbot, instructing it to ignore previous guidelines, query private data stores, and send emails, leading to unauthorized access and privilege escalation.

### Scenario #2: Indirect Injection
A user employs an LLM to summarize a webpage containing hidden instructions that cause the LLM to insert an image linking to a URL, leading to exfiltration of the private conversation.

### Scenario #3: Unintentional Injection
A company includes an instruction in a job description to identify AI-generated applications. An applicant, unaware of this instruction, uses an LLM to optimize their resume, inadvertently triggering the AI detection.

### Scenario #4: Intentional Model Influence
An attacker modifies a document in a repository used by a Retrieval-Augmented Generation (RAG) application. When a user's query returns the modified content, the malicious instructions alter the LLM's output, generating misleading results.

### Scenario #5: Code Injection
An attacker exploits a vulnerability (CVE-2024-5184) in an LLM-powered email assistant to inject malicious prompts, allowing access to sensitive information and manipulation of email content.

### Scenario #6: Payload Splitting
An attacker uploads a resume with split malicious prompts. When an LLM is used to evaluate the candidate, the combined prompts manipulate the model's response, resulting in a positive recommendation despite the actual resume contents.

### Scenario #7: Multimodal Injection
An attacker embeds a malicious prompt within an image that accompanies benign text. When a multimodal AI processes the image and text concurrently, the hidden prompt alters the model's behavior, potentially leading to unauthorized actions or disclosure of sensitive information.

### Scenario #8: Adversarial Suffix
An attacker appends a seemingly meaningless string of characters to a prompt, which influences the LLM's output in a malicious way, bypassing safety measures.

### Scenario #9: Multilingual/Obfuscated Attack
An attacker uses multiple languages or encodes malicious instructions (e.g., using Base64 or emojis) to evade filters and manipulate the LLM's behavior.

---

## Prevention and Mitigation Strategies

### 1. Constrain Model Behavior
Provide specific instructions about the model's role, capabilities, and limitations within the system prompt. Enforce strict context adherence, limit responses to specific tasks or topics, and instruct the model to ignore attempts to modify core instructions.

### 2. Define and Validate Expected Output Formats
Specify clear output formats, request detailed reasoning and source citations, and use deterministic code to validate adherence to these formats.

### 3. Implement Input and Output Filtering
Define sensitive categories and construct rules for identifying and handling such content. Apply semantic filters and use string-checking to scan for non-allowed content. Evaluate responses using the RAG Triad: Assess context relevance, groundedness, and question/answer relevance to identify potentially malicious outputs.

### 4. Enforce Privilege Control and Least Privilege Access
Provide the application with its own API tokens for extensible functionality, and handle these functions in code rather than providing them to the model. Restrict the model's access privileges to the minimum necessary for its intended operations.

### 5. Require Human Approval for High-Risk Actions
Implement human-in-the-loop controls for privileged operations to prevent unauthorized actions.

### 6. Segregate and Identify External Content
Separate and clearly denote untrusted content to limit its influence on user prompts.

### 7. Conduct Adversarial Testing and Attack Simulations
Perform regular penetration testing and breach simulations, treating the model as an untrusted user to test the effectiveness of trust boundaries and access controls.

---

## Reference Links

1. [ChatGPT Plugin Vulnerabilities – Chat with Code](https://embracethered.com/blog/posts/2023/chatgpt-plugin-vulns-chat-with-code/) — Embrace the Red
2. [ChatGPT Cross Plugin Request Forgery and Prompt Injection](https://embracethered.com/blog/posts/2023/chatgpt-cross-plugin-request-forgery-and-prompt-injection./) — Embrace the Red
3. [Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/pdf/2302.12173.pdf) — Arxiv
4. [Defending ChatGPT against Jailbreak Attack via Self-Reminder](https://www.researchsquare.com/article/rs-2873090/v1) — Research Square
5. [Prompt Injection attack against LLM-integrated Applications](https://arxiv.org/abs/2306.05499) — Cornell University
6. [Inject My PDF: Prompt Injection for your Resume](https://kai-greshake.de/posts/inject-my-pdf) — Kai Greshake
7. [Threat Modeling LLM Applications](https://aivillage.org/large%20language%20models/threat-modeling-llm/) — AI Village
8. [Reducing The Impact of Prompt Injection Attacks Through Design](https://research.kudelskisecurity.com/2023/05/25/reducing-the-impact-of-prompt-injection-attacks-through-design/) — Kudelski Security
9. [Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf) — NIST
10. [A Survey of Attacks on Large Vision-Language Models](https://arxiv.org/abs/2407.07403) — Arxiv
11. [Exploiting Programmatic Behavior of LLMs: Dual-Use Through Standard Security Attacks](https://ieeexplore.ieee.org/document/10579515) — IEEE
12. [Universal and Transferable Adversarial Attacks on Aligned Language Models](https://arxiv.org/abs/2307.15043) — Arxiv
13. [From ChatGPT to ThreatGPT: Impact of Generative AI in Cybersecurity and Privacy](https://arxiv.org/abs/2307.00691) — Arxiv

---

## Related Frameworks and Taxonomies

- [AML.T0051.000 – LLM Prompt Injection: Direct](https://atlas.mitre.org/techniques/AML.T0051.000) — MITRE ATLAS
- [AML.T0051.001 – LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001) — MITRE ATLAS
- [AML.T0054 – LLM Jailbreak Injection: Direct](https://atlas.mitre.org/techniques/AML.T0054) — MITRE ATLAS
