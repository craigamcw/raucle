# Raucle Control Mapping: NCSC Cyber Assessment Framework (CAF v3.2)

This document maps raucle's controls to the NCSC [Cyber Assessment Framework
(CAF)](https://www.ncsc.gov.uk/collection/cyber-assessment-framework) v3.2 and the
NCSC [security principles for AI/ML systems](https://www.ncsc.gov.uk/collection/machine-learning-principles).
It is written for CISOs and risk owners evaluating raucle against the framework
that UK government departments, NCSC, and NIS-regulated operators use to assess
cyber security posture.

Raucle is an **agent governance layer**: it does not replace existing security
controls, it adds the missing control plane for AI agents operating inside
regulated environments. Where a CAF objective concerns the agent layer - authorising
what agents may do, proving what they did, detecting when they misbehave - raucle
provides direct, evidenced support. Where a CAF objective concerns infrastructure
raucle does not own (endpoint hardening, network resilience, staff training),
raucle is out of scope and this document says so.

The mapping uses the CAF achievement scale terminology. A control marked
**Direct** addresses the IGP (Indicator of Good Practice) directly. **Supporting**
means raucle contributes evidence one of the IGP statements needs. **Partial**
means raucle covers part of the principle and other controls are required.
**Out of scope** means the principle concerns assets raucle does not govern.

---

## Part 1: CAF v3.2 Objective Mapping

### Objective A - Managing Security Risk

#### Principle A1 - Governance

Raucle provides the **governance instrument** for the AI-agent layer specifically.
Where an organisation's security governance defines *who may do what*, raucle
implements that definition *for agents* as executable, signed policy.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Board-level understanding and direction of security approach | Policy DSL lets risk owners express agent-authorisation policy in reviewable YAML, reviewed and approved through the admin panel. Policies are versioned artefacts, not buried code. | Supporting |
| Security governance structures and responsibilities | Role-based admin access (admin / operator / auditor) with TOTP MFA enforces separation between who *writes* policy, who *operates* the gate, and who *audits* decisions. | Direct (agent layer) |
| Policies reviewed and updated | Hot-reload of policy files; every change is a re-minted, signed capability set, so the currently-enforced policy is always inspectable. | Direct (agent layer) |

#### Principle A2 - Risk Management

The CAF expects risk assessments grounded in threat assumptions and evidence
that decision-makers can consume. Raucle's receipts turn agent activity from an
unmeasurable risk into a **quantified, auditable one**.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Risk assessments based on defined threat assumptions | The capability gate is fail-closed: an agent can only act within an explicitly minted capability. Deny-by-default is the encoded threat assumption. | Direct (agent layer) |
| Risk assessment outputs consumable by decision-makers | Compliance reports map receipt chains to EU AI Act, ISO 42001, and SOC 2 controls; the admin dashboard presents allow/deny/escalate statistics per tool and per agent. | Direct |
| Risk management is continuous, not one-off | Every gate decision produces a signed receipt; chains verify offline; the connection log gives live per-agent risk visibility. | Direct (agent layer) |
| Understanding of the impact of compromise | Escalation thresholds (`require_approval_when`) let risk owners pre-define which agent actions are high-impact and require human approval. | Direct (agent layer) |

#### Principle A3 - Asset Management

Agents themselves - their identities, their capabilities, their connections - are
a new asset class most organisations cannot currently inventory. Raucle is the
**asset register for the agent layer**.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Data, systems and dependencies understood | Every tool an agent may call is enumerated in policy; unknown tools are denied by default; the topology view renders the full source -> gate -> destination inventory live. | Direct (agent layer) |
| Ownership and purpose of assets understood | Agent passports (`issue_passport`) bind each agent to an issuer-countersigned, registry-anchorable identity document. | Direct (agent layer) |
| Knowledge of where data flows | Source/destination matching on every connection record shows exactly which agent talked to which system, with policy provenance. | Direct (agent layer) |

#### Principle A4 - Supply Chain

Third-party agents and agent platforms are supply-chain dependencies; raucle
governs them on first contact.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Supplier dependencies understood and managed | The trust registry anchors issuer keys behind signed checkpoints; a capability only verifies if its issuer is registered, giving supply-chain pinning for agent authority. | Direct (agent layer) |
| Third-party services secured where used | The gateway enforces policy on agents regardless of vendor; cross-org handshake protocol establishes mutual trust between organisations before agent delegation. | Direct (agent layer) |
| Assurance that suppliers meet requirements | Receipts prove *which* authority signed a capability and *what constraints* it carried - the delegation chain is reconstructable. | Supporting |

---

### Objective B - Protecting against cyber attack

#### Principle B1 - Service Protection Policies and Processes

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Policies and procedures defined and implemented | The policy DSL *is* the implemented protection policy for agent actions - not a document, an executable control. | Direct (agent layer) |
| Configuration consistent and managed | Gateway configuration is editable through an authenticated admin API and persisted to a versioned YAML file; Docker deployment is reproducible. | Supporting |

#### Principle B2 - Identity and Access Control

This is raucle's core principle. The CAF states: *"Users (or automated functions)
that can access data or systems are appropriately verified, authenticated and
authorised."* Agents **are** automated functions, and the CAF's language anticipates
exactly the problem raucle solves.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Robust verification, authentication and authorisation | The capability gate enforces Ed25519-signed capability tokens: agent identity (key-pinned), authorisation scope (tool + constraint set), expiry, attenuation chain, and revocation via the trust registry. Calls outside the signed capability structurally cannot execute. | **Direct** |
| Users and systems individually identified | Agent passports and per-agent capability tokens; receipts record the agent's key ID on every action. | **Direct** |
| Privileged access controlled and monitored | Human-in-the-loop escalation (`require_approval_when`) routes high-risk agent actions to a human approver; approval events are receipted. | **Direct** |
| Access permissions granted on need and revoked when no longer required | Capabilities carry TTLs; revocation is enforced through the registry; `attenuate()` only ever narrows. | **Direct** |
| Authentication credentials protected | Signing keys can be held in AWS KMS / Azure Key Vault / HashiCorp Vault (HSM-backed) - the private key never leaves the hardware boundary. Admin panel enforces TOTP MFA on key management. | **Direct** (signing); admin panel MFA |
| Number of accounts with privileged access understood | Policy files enumerate every agent and every tool - the full privilege surface is reviewable in one artefact. | Direct (agent layer) |

#### Principle B3 - Data Security

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Understanding of data important to essential functions | Receipts record what data each agent action touched (as content-addressed hashes by default - privacy by design); the connection log shows data flows between agents and systems. | Direct (agent layer) |
| Data in transit protected | Recommended deployment terminates TLS at the Caddy reverse proxy with HSTS; the gateway itself runs isolated on an internal Docker network. | Supporting (deployment provides; raucle documents and ships the reference architecture) |
| Data at rest protected | Audit chain is hash-chained with Ed25519-signed checkpoints; tamper-evidence is cryptographic, so integrity survives even if confidentiality is managed elsewhere. | **Direct** (integrity); confidentiality relies on the host platform |

#### Principle B4 - System Security

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Secure by design, attack surface minimised | The gate is a structural control, not a classifier: prompt injection cannot bypass it because enforcement happens on signed capability constraints, not on the model's judgement. Proven empirically: a live LLM following an injected "admin mode" instruction was still denied a transfer exceeding its capability. | **Direct** (agent layer) |
| Security engineered and specified | Three soundness theorems mechanised in Lean 4 (attenuation cannot broaden permissions; ALLOW implies constraint satisfaction; proof-carrying calls). Published, reproducible proofs. | **Direct** (agent layer) |
| Vulnerabilities managed | Receipts of *denied* actions are an intrusion record: attempted policy violations are signed, timestamped evidence. | Supporting |

#### Principle B5 - Resilient Networks and Systems

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Resilience against attack and failure | Fail-closed gate: if the policy is missing, the issuer unknown, or the capability expired, the action is denied. The gateway is stateless for gate decisions and horizontally scalable. | Direct (agent layer) |
| Availability of essential services | Out of scope - raucle governs authorisation, not infrastructure availability. | Out of scope |

#### Principle B6 - Staff Awareness and Training

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Users aware of risks and trained | Out of raucle's control scope, though the admin panel's readable policy format and topology view lower the comprehension barrier for risk owners. | Out of scope (training content) |

---

### Objective C - Detecting cyber security events

#### Principle C1 - Security Monitoring

This is where raucle's receipts differentiate. CAF C1 wants monitoring data that
allows *"timely identification of security events"* and the ability to *"audit the
activities of users"*.

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Data collected on security-relevant activity | **Every** gate decision - allow, deny, escalate - produces a signed receipt; the connection log records source, destination, tool, policy, decision, reason, and latency for every call. | **Direct** |
| Ability to audit user (agent) activities | Receipt chains verify offline with published keys; tampered, missing, or reordered receipts are cryptographically detectable. The operator holds no verification advantage the auditor cannot reproduce. | **Direct** |
| Detection of IoCs | Deny/escalate events stream to SIEM (Splunk HEC, Elasticsearch, Azure Sentinel) in real time; burst-of-denials patterns (a probing agent) are visible in the stats dashboard. | **Direct** (events); pattern matching belongs to the SIEM |
| Log data secured against modification | Hash-chained, Ed25519-signed checkpoints make the audit chain append-only in effect: no system or user can modify or delete master copies without detection - precisely C1.b's requirement. | **Direct** |

#### Principle C2 - Proactive Security Event Discovery

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Proactive discovery of security events | Escalation thresholds surface risky agent behaviour *before* execution, not after. The prompt-injection detection engine (PI-001..PI-004 etc.) scans inputs/outputs independently of the gate. | Supporting (the gate provides the events; proactive analysis is the SIEM's/analyst's role) |

---

### Objective D - Minimising the impact of cyber security incidents

#### Principle D1 - Response and Recovery Planning

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Incident response plans in place | Raucle's contribution is forensic readiness: the signed receipt chain *is* the incident timeline. Rebuilding who did what, under whose authority, is a verify operation, not an investigation scramble. | Direct (evidence) |
| Evidence available to support investigations | Receipts are content-addressed and independently verifiable by a third party (regulator, court, insurer) without contacting the operator. | **Direct** |
| Limiting the impact of incidents | Live capability revocation through the trust registry stops a compromised agent's authority at the next check; escalation holds suspected actions before execution. | Direct (agent layer) |

#### Principle D2 - Lessons Learned

| CAF IGP | Raucle contribution | Level |
|---|---|---|
| Lessons learned improve security | Deny reasons are specific (constraint violated, issuer unknown, TTL expired), giving actionable feedback loops into policy revision. The compliance report's control-level summary turns incident data into measurable posture change. | Supporting |

---

## Part 2: NCSC Machine Learning Security Principles Mapping

The NCSC [ML principles](https://www.ncsc.gov.uk/collection/machine-learning-principles)
address the ML system lifecycle. Raucle maps most strongly to the deployment
and operation sections, and specifically implements the guidance NCSC gives for
the rules-on-top pattern.

### NCSC's own words anticipate raucle

The NCSC's [Thinking about the security of AI systems](https://www.ncsc.gov.uk/blog-post/thinking-about-security-ai-systems)
states:

> "no model exists in isolation... what we can do is design the whole system with
> security in mind... A simple example would be applying a **rules-based system on
> top of the ML model to prevent it from taking damaging actions, even when
> prompted to do so**."

Raucle is that rules-based system, formalised: signed capabilities instead of
soft rules, structural enforcement instead of advisory filters.

| NCSC ML principle | Raucle contribution | Level |
|---|---|---|
| **1.2 Model the threats to your system** | Raucle's spec threat model (provenance threats, misattribution, confused-deputy) with published test vectors, incl. the OWASP #177 principal-misattribution vectors contributed by an external researcher. | Supporting |
| **1.4 Analyse vulnerabilities against inherent ML threats** | The benchmark harness measures the gate against injection attacks (100% block rate on attacker-controlled tool calls across 720 AgentDojo attempts); prompt injection is demonstrated not to bypass the capability gate. | **Direct** (evidence source) |
| **2.1 Secure your supply chain** | Trust registry with signed checkpoints; issuer pinning on capabilities; cross-org handshake for agent delegation across organisational boundaries. | Direct (agent authority chain) |
| **3.1 Protect information that could be used to attack your model** | Receipts hash call arguments by default; the compliance report aggregates evidence without exposing raw data. Privacy by default. | Supporting |
| **3.2 Monitor and log user activity** | **This is raucle's core ML-principle match.** Every agent action receipted, chained, signable by external auditors; SIEM streaming; live dashboards. NCSC's goal "you can detect unusual activity patterns" maps directly to the per-agent decision statistics and escalation events. | **Direct** |
| **4.2 Appropriately sanitise inputs** | The scanner sanitises/classifies inputs before they reach the model (PI-001..), and the gate constrains what the model's tool calls may do regardless of input. | **Direct** (tool-call channel); prompt-channel sanitisation is advisory |
| **4.3 Incident and vulnerability management** | Signed forensic timeline; deny/escalate events into SIEM for incident tooling; revocation for containment. | **Direct** (evidence + containment) |
| **5.2 Lessons learned** | Constraint-level deny reasons feed measurable policy iteration. | Supporting |

### The Guidelines for secure AI system development

The joint [Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)
(secure design / development / deployment / operation) include this requirement
in secure design:

> "if AI components need to trigger actions... **you apply appropriate restrictions
> to the possible actions** (this includes external AI and non AI fail-safes if
> necessary)"

and in secure operation:

> "you apply appropriate checks... **requiring users to log in and confirm before
> sending potentially sensitive information**"

Raucle implements both mechanically: the capability gate *is* the restriction on
AI-triggered actions, and the approval escalation *is* the confirm-before-execution
path for sensitive operations - with a cryptographic record of the confirmation.

---

## Part 3: Summary matrix

| CAF Principle | Raucle coverage |
|---|---|
| A1 Governance | Supporting |
| A2 Risk Management | **Direct (agent layer)** |
| A3 Asset Management | **Direct (agent layer)** |
| A4 Supply Chain | **Direct (agent layer)** |
| B1 Service Protection | Supporting |
| B2 Identity and Access Control | **Direct - core principle** |
| B3 Data Security | **Direct (integrity/flows)**; TLS via reference deployment |
| B4 System Security | **Direct (agent layer)** |
| B5 Resilient Networks | Partial (fail-closed gate); availability out of scope |
| B6 Staff Awareness | Out of scope |
| C1 Security Monitoring | **Direct - core principle** |
| C2 Proactive Discovery | Supporting |
| D1 Response and Recovery | **Direct (forensic evidence)** |
| D2 Lessons Learned | Supporting |

**Raucle's strongest CAF contributions are B2 (identity and access control for
automated functions), C1 (security monitoring with tamper-evident logs), and
A2/A3 (risk and asset management for the agent layer).** These are precisely the
CAF principles that CISOs have no existing tooling for once AI agents enter
regulated environments.

---

## Reading this mapping in assessments

- A **CAF self-assessment** for an organisation deploying agents should cite
  raucle receipt chains as the evidence artefact for B2, C1, and D1 IGPs
  concerning automated functions.
- For **NIS Regulations** operators and **GovAssure** purposes, this mapping
  indicates where raucle contributes to a target CAF profile; the *achieved*
  status of any IGP always depends on the whole system, of which raucle is the
  agent-governance component.
- The mapping is deliberately conservative: principles where raucle is only
  supporting or partial are marked as such. Raucle strengthens a CAF case; it
  does not replace infrastructure, endpoint, network, or human-factor controls.

Sources:
- [Cyber Assessment Framework v3.2 (PDF)](https://www.ncsc.gov.uk/sites/default/files/documents/Cyber%20Assessment%20Framework%20V3.2.pdf)
- [Machine learning principles (PDF)](https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-Machine-learning-principles.pdf)
- [Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)
- [Thinking about the security of AI systems](https://www.ncsc.gov.uk/blog-post/thinking-about-security-ai-systems)