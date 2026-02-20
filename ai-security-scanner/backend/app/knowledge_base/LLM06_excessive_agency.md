# OWASP LLM06:2025 - Excessive Agency

**Source:** https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
**OWASP Top 10 for LLM Applications 2025 — Entry #6**

---

## Definition

An LLM-based system is often granted a degree of agency by its developer — the ability to call functions or interface with other systems via extensions (sometimes referred to as tools, skills, or plugins by different vendors) to undertake actions in response to a prompt. The decision over which extension to invoke may also be delegated to an LLM 'agent' to dynamically determine based on input prompt or LLM output. Agent-based systems will typically make repeated calls to an LLM using output from previous invocations to ground and direct subsequent invocations.

Excessive Agency is the vulnerability that enables damaging actions to be performed in response to unexpected, ambiguous, or manipulated outputs from an LLM, regardless of what is causing the LLM to malfunction.

**Common triggers include:**
- Hallucination/confabulation caused by poorly-engineered benign prompts, or just a poorly-performing model
- Direct/indirect prompt injection from a malicious user, an earlier invocation of a malicious/compromised extension, or (in multi-agent/collaborative systems) a malicious/compromised peer agent

**The root cause of Excessive Agency is typically one or more of:**
- Excessive functionality
- Excessive permissions
- Excessive autonomy

Excessive Agency can lead to a broad range of impacts across the confidentiality, integrity, and availability spectrum, and is dependent on which systems an LLM-based app is able to interact with.

> **Note:** Excessive Agency differs from Improper Output Handling (LLM05), which is concerned with insufficient scrutiny of LLM outputs. Excessive Agency is about the scope of actions the LLM can take autonomously.

---

## Vulnerability Types / Common Examples of Risks

### 1. Excessive Functionality (Type A)
An LLM agent has access to extensions which include functions that are not needed for the intended operation of the system. For example, a developer needs to grant an LLM agent the ability to read documents from a repository, but the third-party extension they choose to use also includes the ability to modify and delete documents.

### 2. Excessive Functionality (Type B — Stale Extensions)
An extension may have been trialled during a development phase and dropped in favor of a better alternative, but the original plugin remains available to the LLM agent.

### 3. Excessive Functionality (Type C — Open-Ended Extensions)
An LLM plugin with open-ended functionality fails to properly filter the input instructions for commands outside what's necessary for the intended operation of the application. E.g., an extension to run one specific shell command fails to properly prevent other shell commands from being executed.

### 4. Excessive Permissions (Type A — Overprivileged Identity)
An LLM extension has permissions on downstream systems that are not needed for the intended operation of the application. E.g., an extension intended to read data connects to a database server using an identity that not only has SELECT permissions, but also UPDATE, INSERT, and DELETE permissions.

### 5. Excessive Permissions (Type B — Shared High-Privilege Identity)
An LLM extension that is designed to perform operations in the context of an individual user accesses downstream systems with a generic high-privileged identity. E.g., an extension to read the current user's document store connects to the document repository with a privileged account that has access to files belonging to all users.

### 6. Excessive Autonomy
An LLM-based application or extension fails to independently verify and approve high-impact actions. E.g., an extension that allows a user's documents to be deleted performs deletions without any confirmation from the user.

---

## Detection Criteria (For Our Scanner)

### High Risk Indicators:
- Database permissions include write/update/delete/admin when only read is needed
- File system access includes write or execute permissions
- Shell execution capabilities present (os.system, subprocess, exec) without restrictions
- HTTP client with unrestricted outbound access (no allowlist/denylist)
- Administrative privilege grants to LLM agent
- No human approval required for destructive or irreversible actions (delete, send, post, execute)
- Agent can send emails, post to social media, or make purchases autonomously
- Multi-agent system where agents can invoke each other without authorization checks
- Extensions available to LLM that are no longer needed (stale plugins)
- Open-ended shell/command execution extensions

### Medium Risk Indicators:
- Permissions broader than minimum necessary for stated purpose
- No rate limiting on agent actions
- No logging or audit trail of agent actions
- Agent operates with shared/generic identity rather than user-specific identity
- No scope restrictions on OAuth tokens used by extensions
- Missing confirmation step for medium-impact actions

### Low Risk / Secure Patterns:
- Principle of least privilege enforced: only minimum necessary permissions granted
- Human-in-the-loop controls for all high-impact actions
- Extensions limited to specific, granular functions (not open-ended)
- User-specific OAuth tokens with minimum required scope
- Complete mediation: all downstream requests validated against security policies
- Rate limiting implemented on agent actions
- Comprehensive logging and monitoring of all agent actions
- Stale/unused extensions removed from agent's available tools

---

## Attack Scenarios

### Primary Attack Scenario: Email Exfiltration via Excessive Agency
An LLM-based personal assistant app is granted access to an individual's mailbox via an extension in order to summarise the content of incoming emails. To achieve this functionality, the extension requires the ability to read messages; however, the plugin that the system developer has chosen to use also contains functions for sending messages.

Additionally, the app is vulnerable to an indirect prompt injection attack, whereby a maliciously-crafted incoming email tricks the LLM into commanding the agent to scan the user's inbox for sensitive information and forward it to the attacker's email address.

**This could be avoided by:**
- Eliminating excessive functionality by using an extension that only implements mail-reading capabilities
- Eliminating excessive permissions by authenticating to the user's email service via an OAuth session with a read-only scope
- Eliminating excessive autonomy by requiring the user to manually review and hit 'send' on every mail drafted by the LLM extension

Alternatively, the damage caused could be reduced by implementing rate limiting on the mail-sending interface.

---

## Prevention and Mitigation Strategies

### 1. Minimize Extensions
Limit the extensions that LLM agents are allowed to call to only the minimum necessary. For example, if an LLM-based system does not require the ability to fetch the contents of a URL then such an extension should not be offered to the LLM agent.

### 2. Minimize Extension Functionality
Limit the functions that are implemented in LLM extensions to the minimum necessary. For example, an extension that accesses a user's mailbox to summarise emails may only require the ability to read emails, so the extension should not contain other functionality such as deleting or sending messages.

### 3. Avoid Open-Ended Extensions
Avoid the use of open-ended extensions where possible (e.g., run a shell command, fetch a URL, etc.) and use extensions with more granular functionality. For example, an LLM-based app may need to write some output to a file. If this were implemented using an extension to run a shell function then the scope for undesirable actions is very large (any other shell command could be executed). A more secure alternative would be to build a specific file-writing extension that only implements that specific functionality.

### 4. Minimize Extension Permissions
Limit the permissions that LLM extensions are granted to other systems to the minimum necessary in order to limit the scope of undesirable actions. For example, an LLM agent that uses a product database in order to make purchase recommendations to a customer might only need read access to a 'products' table; it should not have access to other tables, nor the ability to insert, update, or delete records. This should be enforced by applying appropriate database permissions for the identity that the LLM extension uses to connect to the database.

### 5. Execute Extensions in User's Context
Track user authorization and security scope to ensure actions taken on behalf of a user are executed on downstream systems in the context of that specific user, and with the minimum privileges necessary. For example, an LLM extension that reads a user's code repo should require the user to authenticate via OAuth and with the minimum scope required.

### 6. Require User Approval (Human-in-the-Loop)
Utilise human-in-the-loop control to require a human to approve high-impact actions before they are taken. This may be implemented in a downstream system (outside the scope of the LLM application) or within the LLM extension itself. For example, an LLM-based app that creates and posts social media content on behalf of a user should include a user approval routine within the extension that implements the 'post' operation.

### 7. Complete Mediation
Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not. Enforce the complete mediation principle so that all requests made to downstream systems via extensions are validated against security policies.

### 8. Sanitise LLM Inputs and Outputs
Follow secure coding best practice, such as applying OWASP's recommendations in ASVS (Application Security Verification Standard), with a particularly strong focus on input sanitisation. Use Static Application Security Testing (SAST) and Dynamic and Interactive application testing (DAST, IAST) in development pipelines.

### Additional Damage-Limiting Controls (Do Not Prevent, But Reduce Impact):
- Log and monitor the activity of LLM extensions and downstream systems to identify where undesirable actions are taking place, and respond accordingly
- Implement rate-limiting to reduce the number of undesirable actions that can take place within a given time period, increasing the opportunity to discover undesirable actions through monitoring before significant damage can occur

---

## Reference Links

1. [Slack AI data exfil from private channels](https://promptarmor.substack.com/p/slack-ai-data-exfiltration-from-private) — PromptArmor
2. [Rogue Agents: Stop AI From Misusing Your APIs](https://www.twilio.com/en-us/blog/rogue-ai-agents-secure-your-apis) — Twilio
3. [Embrace the Red: Confused Deputy Problem](https://embracethered.com/blog/posts/2023/chatgpt-cross-plugin-request-forgery-and-prompt-injection./) — Embrace The Red
4. [NeMo-Guardrails: Interface guidelines](https://github.com/NVIDIA/NeMo-Guardrails/blob/main/docs/security/guidelines.md) — NVIDIA Github
5. [Simon Willison: Dual LLM Pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/) — Simon Willison

---

## Related Frameworks and Taxonomies

- OWASP ASVS V1: Architecture, Design and Threat Modeling (Least Privilege)
- OWASP ASVS V4: Access Control
- CWE-272: Least Privilege Violation
- CWE-732: Incorrect Permission Assignment for Critical Resource
- NIST SP 800-53 AC-6: Least Privilege
- MITRE ATT&CK: T1548 – Abuse Elevation Control Mechanism
