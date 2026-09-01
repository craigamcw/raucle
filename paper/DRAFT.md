# Verified Capability Discipline for LLM Agent Tool Calls

*Draft v2 — 2026-05-17 (empirical sweep landed; see `paper/eval/runs/README.md` for the run history and `paper/eval/results/*.json` for per-cell aggregates).*

---

## 1. Introduction

Large language model agents now mediate billions of tool calls per day across customer support, financial services, software engineering, and clinical workflows. Every one of those calls is the output of a stochastic system whose input surface is, by construction, the open set of all natural language. Four years of work on prompt-injection defence has converged on a stable observation: text-side defences against text-side attacks improve attack-success rates from catastrophic to merely poor. The strongest published results in 2024-2026 — Spotlighting [@hines2024defending], StruQ [@chen2024struq], constitutional classifiers [@anthropic2024constitutional], and the suite of commercial prompt-shield products — reduce the AgentDojo [@debenedetti2024agentdojo] and InjecAgent [@zhan2024injecagent] attack success rate (ASR) from a no-defence baseline of roughly half to between 14% and 31%. Half of one in three attempts still succeeds.

The diagnosis we offer is that the defences are operating in the wrong shape of problem. Verifying properties of unbounded natural language is open; the agent's downstream effect on the world, however, is mediated almost entirely through a much narrower interface. Every modern agent framework — OpenAI function-calling, Anthropic tool use, the Model Context Protocol, AutoGen, and LangChain among them — requires tools to declare structured input grammars, typically JSON Schema. Over those grammars the set of well-formed strings is bounded, the propositions one wants to enforce are decidable, and the enforcement point can be moved out of the model entirely.

This paper presents Verified Capability Discipline (VCD), a composition of three primitives that together provide **portable, cryptographically-verifiable authorisation** for LLM agent tool calls. We use SMT to prove that a tool's security policy is satisfied over every string its JSON Schema permits, or to extract a concrete counterexample call. We bind the proven policy into an Ed25519-signed capability token whose attenuation primitives mechanically forbid permission broadening. We place a gate on the only path from agent intent to tool execution and require every call to carry a token whose constraints are satisfied by the actual call arguments. The artefact a deployment produces — the *capability receipt*, a signed record citing the issuer, the schema hash, the policy proof hash, the Lean theorem identifier, the attenuation chain, and a hash of the actual call arguments — is portable across organisations, clouds, and trust boundaries, and is the kind of evidence that regulators, internal auditors, and downstream tool implementations can independently verify without sharing a secret with the issuer.

We frame the contribution as authorisation rather than defence deliberately. The prompt-injection literature has spent five years asking whether the *model* can be made robust to adversarial input; in parallel, model-side advances such as instruction/data embedding separation (ASIDE [@zverev2025aside]) and preference-aligned training (SecAlign [@chen2025secalign]) are pushing baseline ASRs downward at the model layer, and 2026's hyperscaler-bundled prompt-shield products advertise the same goal. The defensive landscape is converging. The authorisation question is orthogonal and remains open: even when the model is robust, an agent acting in regulated environments must produce a portable, auditable record of *what it was authorised to do, by whom, against what verified policy, and what it actually did*. VCD's primitives are the first published combination — SMT-verified policy completeness, Lean-mechanised attenuation soundness, content-addressed signed capabilities — that produces such a record. The empirical attack-success reduction we report against contemporary prompt-injection benchmarks is a strong demonstration that the authorisation layer is also a competitive defence; the durable contribution is the artefact.

The contribution is neither the SMT verification nor the capability discipline taken alone — both have decades of prior art that we discuss in Section 7 — but the specific composition, the empirical demonstration that it holds against state-of-the-art prompt-injection benchmarks at production-acceptable latency, and the production of a portable cryptographic audit primitive. We mechanise three soundness theorems in Lean 4, evaluate against AgentDojo [@debenedetti2024agentdojo] and InjecAgent [@zhan2024injecagent] alongside contemporary text-side defences (Spotlighting [@hines2024defending], Microsoft Prompt Shields), and release the reference implementation, Lean development, and benchmark harness as open source under a permissive licence (Apache-2.0).

Our principal claims are:

1. **Structural enforcement.** If the gate returns ALLOW for a tool call, the call arguments satisfy every constraint in a valid descendant of a capability token signed by a pinned issuer; absent compromise of the issuer's private key, no agent input — natural-language or otherwise — can produce an ALLOW for arguments that violate the policy.
2. **Provable policy completeness.** Given a tool's JSON Schema in a supported fragment, the prover terminates with either a proof that no string in the schema's language violates the policy, or a concrete counterexample call.
3. **Portable audit primitive.** Every gate decision produces a *capability receipt*: a content-addressed, Ed25519-signed record citing the issuer's public key, the verified JSON Schema, the cited policy proof, the Lean soundness theorem id, the full attenuation chain, and the call argument hash. The receipt is verifiable by any third party — including downstream tool implementations, partner organisations, and external auditors — without sharing a secret with the issuer. To our knowledge, no prior agent-security work produces an artefact with this combination of properties.
4. **Empirical attack-success reduction.** Across three frontier-class open-weight models (deepseek-v3.2, deepseek-v4-flash, deepseek-v4-pro), three attack families (`important_instructions`, `direct`, `ignore_previous`), and four AgentDojo task suites (banking, slack, travel, workspace), VCD reduces the tool-call-mediated attack-success rate from a no-defence baseline of **1.4–70.8%** to a benchmark-artefact floor of **0.0–0.7%**, while preserving **58.6–91.0%** benign task completion. The strongest contemporary text-side defence we compared (prompt-shields, DeBERTa-based PI detector) achieves equivalent ASR but collapses benign task completion to **0.0–36.7%** on the same cells — a **+27.9 to +58.6 percentage-point** benign-preservation gap at equivalent security. A static upper bound (§6.2.1) establishes that the gate's constraint logic denies every catalogued attack across both benchmarks' 2,737 user-task × injection-task pairs. Every non-zero LLM-driven ASR cell we report (720 banking attempts) maps to the same `user_task_15 × injection_task_4` IBAN-coincidence benchmark artefact in which the user's authorised tool call legitimately matches the attacker's adversarial target; outside that single cell, the LLM-driven gate-block rate on attacker-controlled tool calls is **100%**. Per-call gate latency is well under 100 microseconds at p50 on commodity hardware, and end-to-end agent wall time with VCD enabled is at or below the unprotected baseline on four of eight cohorts measured (§6.3.1).

We argue in Section 9 that VCD does not solve prompt injection — free-form output attacks and side-channel exfiltration over allowed parameters are out of scope — but that it closes the dominant attack class, and that the trajectory of AI security must be to move enforcement boundaries out of the model and into structural gates wherever the grammar permits.

We adopt the convention throughout this paper of being conspicuously honest about the boundary of our claims. Section 2 enumerates the out-of-scope attack classes; Section 6.5 reports the configurations in which VCD did *not* eliminate attack success. The narrowness of the claim is what makes it credible.

The remainder of this paper is organised as follows. Section 2 fixes the threat model. Section 3 describes the three primitives and their composition. Section 4 states and sketches the three soundness theorems. Section 5 describes the implementation. Section 6 reports the empirical evaluation. Section 7 places VCD in the related literature. Section 8 discusses limitations.

## 2. Threat Model

We adopt the standard agentic-LLM adversary model from Greshake et al. [@greshake2023not] and Debenedetti et al. [@debenedetti2024agentdojo], with explicit cryptographic assumptions.

**Adversary capabilities.** The adversary controls any untrusted input the agent ingests: the user message, the contents of RAG-retrieved documents, the output of any third-party tool whose result is fed back into the agent's context, web pages the agent browses, and email or chat messages the agent reads. The adversary observes the agent's system prompt, the list of tools available to the agent, the JSON Schema of every tool, and — in our most pessimistic configuration — the constraint policy carried by the capability token in force at the time of the attack. The adversary cannot forge Ed25519 signatures, cannot compromise the issuer's private signing key, cannot execute code inside the gate process, and cannot tamper with the audit log after the fact.

**Defender capabilities.** The defender controls a gate process that sits between the agent runtime and the tool implementations. The gate runs in a separate trust domain from the model — a separate process, container, or address space — and is the only path through which tools are invoked. The defender holds the issuer's private key in a hardware security module or equivalent. The defender authors tool JSON Schemas and constraint policies; we make no assumption that either is correct, only that the SMT prover catches the cases where they disagree.

**Token confidentiality.** Capability tokens are *unforgeable* but not *confidential*: an attacker who steals a valid token can use it within its bounds. Production deployments should bind each token to a session via a confidential channel (mTLS between agent and gate; per-session token rotation; short TTLs) so that exfiltrated tokens are useless to attackers operating in different sessions. The reference implementation does not enforce this binding — it is the responsibility of the deployment. The threat model in this paper assumes tokens cannot be exfiltrated from the agent runtime; this assumption is realistic for in-process deployments and weakens to "tokens have short TTL and are bound to session keys" in the multi-tenant case.

**Security goal.** For every tool call $c = (\text{tool}, \text{args})$ that the gate authorises with token $t$, the arguments $\text{args}$ satisfy every constraint in $t$, and $t$ is a valid descendant of a root token signed by a pinned issuer. We refer to this property as *gate soundness*. We also require *attenuation soundness*: no child token derived from a parent can carry permissions broader than the parent along any constraint dimension or lifetime.

**Operational definition of "tool-call-mediated."** Throughout this paper an attack is *tool-call-mediated* iff its success criterion is the invocation of a specific tool with specific argument values. This matches AgentDojo's `security` boolean and InjecAgent's success predicate exactly. An attack whose success criterion is, for example, the agent *speaking aloud* a secret it previously retrieved through a tool — without subsequently emitting a structured tool call to exfiltrate it — is **not** tool-call-mediated under this definition, regardless of whether a tool call earlier in the trace produced the secret. We make no claim against the non-tool-call-mediated class; see §6.5.

**Out of scope.** We list explicitly what VCD does *not* claim. Free-form natural-language output attacks — for example, an attacker coercing the agent to reveal a secret in its visible response — remain unaddressed; the bounded-grammar argument does not apply. Side-channel exfiltration through allowed parameter values (an `amount` field accepting any 64-bit integer permits up to 64 bits per call of covert content) is not prevented; we discuss in Section 8 how schema tightening reduces this channel. Confused-deputy attacks across multiple legitimately-authorised tool calls — read mailbox, then exfiltrate via legitimate `send_email` — are partially addressed by our companion provenance layer [omitted for blind review] but are not the focus of this paper. The model itself is not part of the trusted computing base; the gate is. Compromise of the gate process or the issuer's signing key is outside the model.

**Trust boundary of the gate.** Because the gate's integrity is load-bearing for every claim in this paper, we are explicit about what its operational profile must look like. The gate runs in a separate process from the agent runtime, with no `eval`, `exec`, or untrusted-deserialisation entry points reachable from agent-controlled data; the issuer's private key resides in a hardware security module or analogous trusted environment; the audit log is written to append-only storage. Standard process-isolation, language-runtime hardening, and key-management practices apply. These requirements are the same as for any cryptographic gateway and are not specific to VCD. An agent runtime compromised by an unrelated vulnerability — RCE into the gate's address space, key exfiltration via memory disclosure — would defeat the property; we are not protecting against operating-system-level compromise.

This threat model is deliberately narrower than the universal "we defend against all prompt injection" claims common in the prior literature. We argue that narrow, well-defined threat models with formal guarantees are more useful to deployers than broad informal claims with statistical guarantees.

## 3. System Design

VCD has three components, each designed to be useful independently but engineered to compose. We describe them in the order they appear in a single end-to-end invocation: schema verification, capability minting, and gate enforcement (Figure 6).

### 3.1 SMT-Backed Policy Verification

Given a tool with JSON Schema $S$ and a security policy $P$, we ask: does every JSON object satisfying $S$ also satisfy $P$? If yes, the policy is *complete* over the schema; if no, there exists a concrete counterexample tool call.

We support a fragment of JSON Schema that has decidable semantics under the combined theory of strings, integers, and booleans in Z3 [@demoura2008z3]: top-level objects with primitive properties (`string`, `number`, `integer`, `boolean`), the `enum` keyword on string-valued properties, `minimum`/`maximum` constraints on numeric properties, and the `required` array. Constructs outside this fragment — recursive references, `oneOf`/`anyOf` schemas, arbitrary regex constraints on string fields, unbounded arrays — cause the prover to raise `UnsupportedGrammar` rather than silently approximate. Section 8 sketches the extensions needed to widen the fragment.

We support a corresponding fragment of policy language. A policy is a mapping from constraint kinds to per-field values: `forbidden_values: {field → [v_1, ..., v_n]}` and `allowed_values: {field → [v_1, ..., v_n]}` for set-valued constraints on string fields; `max_value` and `min_value` for numeric bounds; `required_present: [field, ...]` for additional presence requirements beyond the schema's `required`; and `forbidden_field_combinations: [[f_1, f_2], ...]` for forbidden co-occurrences.

The encoding into Z3 is direct. Each schema property becomes an SMT variable of matching sort. Each property's presence is a Boolean. Schema-level constraints (enum membership, numeric bounds, required presence) are conjuncted as preconditions. The policy is encoded as a *violation* disjunction: a single Z3 query asks whether there exists an assignment satisfying the schema preconditions and at least one violation. If `unsat`, the policy is proven complete. If `sat`, Z3 produces a model from which we extract a concrete counterexample call.

The prover emits a `ProofResult` containing canonical-JSON hashes of the schema and policy, the proof status (`PROVEN`, `REFUTED`, or `UNDECIDED`), and any counterexample. The proof result is itself hashed to produce a content-addressed `proof_hash` that capability tokens can cite.

### 3.2 Capability Tokens

A capability token $t$ is an Ed25519-signed structure binding `(agent_id, tool, constraints, issued_at, not_before, expires_at, parent_id, policy_proof_hash, issuer, key_id)`. The signature covers a canonical-JSON serialisation of the bound fields. The token's identifier is the SHA-256 of the same canonical body, prefixed with `cap:`; the identifier is therefore content-addressed and unforgeable absent collision.

The constraint schema mirrors the policy schema accepted by the prover, by deliberate design: a token can cite the proof's hash and the gate can statically verify that the token's constraints are at least as tight as the proven policy.

**Attenuation.** Given a parent token $p$ held by an authorised principal, the issuer's `attenuate` primitive derives a child token $c$ with: (a) the same `tool` as $p$; (b) an `agent_id` equal to or a prefix-extension of $p$'s; (c) constraints that are *narrower* along every dimension; (d) an `expires_at` no later than $p$'s; (e) `parent_id` set to $p$'s identifier. Narrowing is defined per constraint kind:

| Kind | Narrowing operation |
|---|---|
| `forbidden_values[f]` | union: $c.\text{forbidden}_f \supseteq p.\text{forbidden}_f$ |
| `allowed_values[f]` | intersection: $c.\text{allowed}_f \subseteq p.\text{allowed}_f$ |
| `max_value[f]` | minimum: $c.\text{max}_f \le p.\text{max}_f$ |
| `min_value[f]` | maximum: $c.\text{min}_f \ge p.\text{min}_f$ |
| `required_present` | superset: $c.\text{required} \supseteq p.\text{required}$ |
| `forbidden_field_combinations` | superset: $c.\text{forbidden\_combos} \supseteq p.\text{forbidden\_combos}$ |

Asking `attenuate` for a constraint that would broaden permissions silently retains the parent's tighter bound; asking for a child lifetime that would outlive the parent raises an exception. Both behaviours are mechanically enforced (Section 4).

The attenuation discipline is borrowed directly from the object-capability literature [@miller2006robust] and from Macaroons [@birgisson2014macaroons], from which it differs primarily in the cryptographic substrate (Ed25519 signatures rather than chained HMACs) and the content-addressed identifier (preventing token-ID reassignment attacks that bedevil bearer-token systems).

### 3.3 The Gate

The gate is the only path from agent intent to tool execution. It runs out-of-process from both the model and the tool implementation, accepts a `(token, tool, args)` triple, and returns a `GateDecision` of `ALLOW` or `DENY` with a structured reason. The gate performs eight checks in order, failing closed on any one of them:

1. **Issuer pinning.** The token's `key_id` must appear in the gate's trusted-issuer map; otherwise DENY.
2. **Signature verification.** Verify the Ed25519 signature against the canonical body using the pinned public key.
3. **Identifier binding.** Recompute `cap:` + SHA-256 of the canonical body and compare to the token's `token_id`; reject on mismatch. This blocks an attack where an adversary substitutes a valid signature against a different body.
4. **Time bounds.** Reject if `now < not_before` or `now ≥ expires_at`.
5. **Tool match.** Reject if `token.tool ≠ requested_tool`.
6. **Agent scope.** Reject if the caller's claimed `agent_id` is neither equal to the token's `agent_id` nor a prefix-extension of it.
7. **Constraint satisfaction.** For each constraint kind in the token, evaluate the constraint against the supplied `args`. Reject on any violation.
8. **Chain resolution (optional).** If the token carries a `parent_id`, walk the parent chain. Every intermediate token must verify under the gate's trusted-issuer map. Reject on any unresolved or invalid parent.

The gate is a deterministic, side-effect-free decision procedure. Every invocation emits a structured event suitable for consumption by an append-only audit log; the gate does not itself maintain state.

**Gate-monopoly is an architectural assumption, not a mathematical theorem.** Theorem 2 (§4) establishes that any call returning ALLOW from the gate satisfies the in-force constraints; it does *not* establish that every tool invocation must go through the gate. That latter property is the deployer's responsibility and is enforced architecturally: tool implementations live in a separate process from the agent runtime, exposed only behind a gate-mediated RPC interface, with no eval/exec/direct-import paths reachable from agent-controlled data. The reference implementation ships the gate as an out-of-process server behind a Unix socket or local HTTPS endpoint, with the issuer key in an HSM. A deployment that violates this discipline — for example, by linking the agent runtime and the tool implementation into one address space and letting the agent reach the tool symbol directly — loses the property regardless of the gate's correctness. We call this property out explicitly because §4's mechanisation provides no formal guarantee about it.

### 3.4 Composition

The three primitives compose as follows. A platform operator authors a tool schema and a policy, runs the SMT prover, and on `PROVEN` obtains a `proof_hash`. The operator mints a root capability token citing the proof hash, signing with their issuer key. Tokens are distributed to authorised agent contexts, possibly via attenuation through orchestration layers. At tool-call time, the agent presents its current token to the gate; the gate enforces. Every gate decision is recorded into a hash-chained audit log signed by a separate operational key, providing tamper-evident attribution that is independently verifiable offline.

The four hashes — schema, policy, proof, audit-leaf — and three signatures — issuer (on the token), audit (on the chain checkpoint), gate-decision (optional, on the structured event) — close the trust graph. Every link is content-addressed; every link is verifiable by any party in possession of the corresponding public key. Figure 1 sketches the resulting graph.

```
                  ┌─────────────────┐
                  │  JSON Schema S  │── sha256 ──► grammar_hash
                  └─────────────────┘                   │
                                                        ▼
                  ┌─────────────────┐           ┌──────────────┐
                  │   Policy P      │── sha256 ─►│ proof_hash   │ (PROVEN/REFUTED)
                  └─────────────────┘           └──────────────┘
                                                        │
                                            cited by    │
                                                        ▼
            ┌──────────────────────────────────────────────────┐
            │  Capability Token   (Ed25519, content-addressed) │
            │  (agent, tool, constraints, nbf, exp,            │
            │   policy_proof_hash, parent_id)                  │
            └──────────────────────────────────────────────────┘
                                │                       │
                       attenuate│                       │ presented at call site
                                ▼                       ▼
                       ┌────────────────┐    ┌────────────────────┐
                       │  Child Token   │    │  Gate.check(...)   │
                       │  parent_id=…   │    │  ALLOW or DENY     │
                       └────────────────┘    └────────────────────┘
                                                        │
                                              audit event
                                                        ▼
                                            ┌──────────────────────┐
                                            │  Hash-chained log    │
                                            │  Merkle root, signed │
                                            └──────────────────────┘

Figure 1: The trust graph. Every solid arrow is a content-addressed
reference; every signed artefact is verifiable offline against a pinned
issuer or audit key.
```

## 4. Formal Analysis

We mechanise three theorems in Lean 4 [LEA]. The full development lives in `paper/lean/`; we sketch the statements and proof structure here.

Let $\Sigma$ denote the set of well-formed JSON objects under a fixed schema $S$ in the supported fragment, and $\Pi$ the set of policies in the supported policy fragment. Let $\text{Tok}$ denote the type of capability tokens, $\Pi_\text{tok}: \text{Tok} \to \Pi$ the projection from a token to its constraint set, and $\text{Verify}: \text{Tok} \times \mathcal{K} \to \{0, 1\}$ Ed25519 verification under a public key.

**Theorem 1 (Attenuation Soundness).** *For all $p, c : \text{Tok}$, if $c$ is in the image of $\text{attenuate}(p, \cdot)$, then for every constraint kind $k$ and every field $f$, the narrowing relation $\sqsubseteq_k$ holds between $\Pi_\text{tok}(c)|_{k,f}$ and $\Pi_\text{tok}(p)|_{k,f}$, and $c.\text{expires\_at} \le p.\text{expires\_at}$.*

The proof proceeds by case analysis on $k$. For each constraint kind, `attenuate`'s implementation is shown to compute the appropriate lattice meet (intersection, union, min, max). Because each operation is monotone in the lattice, $\sqsubseteq_k$ is preserved by definition. The lifetime bound follows from the explicit guard in `attenuate` that returns `none` when $c.\text{expires\_at} > p.\text{expires\_at}$. The Lean development is approximately 105 lines and compiles cleanly under Mathlib v4.10.0.

**Theorem 2 (Gate Soundness).** *For all $t : \text{Tok}$, all tools $T$, and all argument bindings $a$, if $\text{Gate.check}(t, T, a) = \text{ALLOW}$ under trusted-issuer set $\mathcal{K}$, then: (i) $t.\text{tool} = T$; (ii) every constraint of the kinds modelled in the development — `allowed_values`, `forbidden_values`, `max_value`, `min_value`, and `required_present` — in $\Pi_\text{tok}(t)$ is satisfied by $a$; (iii) the signature on $t$ verifies under some $k \in \mathcal{K}$; (iv) $t.\text{token\_id} = \text{cap:}\Vert\text{SHA256}(\text{canon}(t.\text{body}))$.*

The proof is a direct case analysis on the gate checks. Each check, if it returned ALLOW, established the corresponding postcondition. The pre-image analysis is mechanical. The Lean development is approximately 95 lines and compiles cleanly.

**Scope of the mechanised constraint vocabulary.** The Lean `Policy` models the five constraint kinds named in clause (ii). The reference implementation's runtime gate enforces four further kinds — `starts_with`, `forbidden_field_combinations`, dot-delimited `agent_id` descendant scope, and a revocation denylist — together with token expiry and issuer pinning. These are covered by the implementation's test suite but are **not** part of the Lean model; extending the mechanisation to them is future work. We therefore state Theorem 2 over the modelled vocabulary and do not claim mechanised soundness for the four runtime-only kinds.

**Theorem 3 (Policy-Proof Composition).** *Let $S$ be a schema, $P$ a policy, and $\rho$ a proof artifact for $(S, P)$ with $\rho.\text{status} = \text{PROVEN}$. Then for every argument binding $a$ that conforms to $S$ and is accepted by the gate under a token $t$ — i.e. $\text{Gate.check}(t, t.\text{tool}, a) = \text{ALLOW}$ — both: (i) $a$ satisfies $P$; and (ii) $a$ satisfies $t$'s own constraints.*

What the mechanised proof establishes, precisely. Clause (i) is discharged by an explicit **prover-soundness axiom** standing for the Z3 oracle: it states that a `PROVEN` artifact for $(S, P)$ certifies $\Sigma \cap \neg P = \emptyset$ — every schema-conforming assignment satisfies $P$ — so $a$'s schema conformance yields $a \models P$ directly. This axiom is **load-bearing** in the proof of clause (i) (it is applied, not merely recorded). Clause (ii) is discharged independently from gate soundness (Theorem 2). What is deliberately *not* mechanised: that the proof $\rho$ pertains to this tool's $(S, P)$ and that $t$ cites it — the $\text{policy\_proof\_hash} \leftrightarrow$ grammar/policy-hash binding — is enforced operationally by the gate's strict proof mode (`_check_proof_binding` in the reference implementation) and is taken as a hypothesis of the theorem rather than re-derived from hashes in Lean. This is the design intent: the SMT solver (via the axiom), not Lean, certifies policy completeness; the runtime gate checks the citation. Consequently the mechanised result is strongest when strict proof mode is enabled — the default gate mode treats `policy_proof_hash` as informational and does not enforce the binding. The Lean development for this theorem is approximately 130 lines. The full development — the shared data model plus Theorems 1–3 — is approximately 430 lines of Lean 4 and compiles under Mathlib v4.10.0 with no `sorry`s.

We are honest about what the Lean development does and does not establish. It mechanises the *attenuation and gate logic at the level of the abstract data model*. It does not mechanise the bit-level correctness of the Ed25519 implementation (we rely on Erbsen et al.'s verified field-arithmetic for Curve25519/Ed25519 [erbsen2019simple] and the audited `cryptography` library [PYCA]) nor the bit-level correctness of Z3 (we treat the SMT solver as a trusted oracle whose `unsat` results we accept; in practice a `PROVEN` result from Z3 should be cross-validated against a second implementation, a step we have added to the reference codebase).

The mechanisation depends on three explicit cryptographic-oracle assumptions, all standard. (i) **Ed25519 unforgeability under chosen-message attack:** the only way to produce a valid signature over a body is to know the corresponding private key. Theorem 2's conclusion that the verifying public key is in the trusted set rests on this. (ii) **SHA-256 collision resistance:** no two distinct canonical bodies hash to the same `token_id`. Theorem 2's identifier-binding check rests on this. (iii) **`canonBody` determinism:** the canonical-JSON serialisation produces the same byte sequence for every logically-equivalent body across implementations and Python versions. Our canonicalisation uses sorted keys, no whitespace, UTF-8 encoding, and `ensure_ascii=False`; we treat this as an oracle property and recommend deployments cross-validate the canonical encoding against a second implementation at boot.

## 5. Implementation

The reference implementation is an open-source library cited as `[anonymised for blind review]`. Approximately 12,000 lines of Python implement the runtime (the SMT prover, capability issuance and the gate, provenance receipts and chain verification, the modelled-language registry described below, the audit chain, the policy-DSL gateway, remote-key signing, and the conformance re-verification layer described below); an additional ~430 lines of Lean 4 contain the formal development. The implementation depends on Z3 (Python bindings) and the audited `cryptography` library for Ed25519. No new cryptographic primitives are introduced.

Several engineering decisions warrant comment.

**Modelled-language registry.** The set of constructs the system reasons about — capability constraint kinds, JSON-Schema keywords, the URL and SQL grammar/policy surfaces, and the provenance chain-envelope fields — is enumerated in a single executable registry. Both the runtime and the test suite derive their allow-lists from it, and a continuous-integration drift test fails if any consumer's modelled set diverges from the registry. This makes fail-closed behaviour a *structural* property rather than a coding convention: a construct absent from the registry hits its dimension's conservative verdict by construction. An unmodelled schema keyword, policy key, URL key, or SQL construct downgrades a would-be `PROVEN` to `UNDECIDED`; an unknown capability constraint kind is rejected at mint; an unknown chain-envelope field is rejected at verification. The registry is the structural mechanism behind Theorem 2's "modelled constraint kinds" qualifier: the gate cannot silently enforce, or fail to enforce, a kind the model does not name.

**Canonical JSON.** All hashes and signature inputs use a canonical-JSON serialisation — sorted keys, no whitespace, UTF-8 encoded, `ensure_ascii=False` — so that the same logical object always produces the same bytes. This avoids signature-mismatch failures that bedevil deployments where serialisation order varies across implementations. The canonical form is a restricted JCS subset: integers only (floats are rejected rather than serialised, because cross-implementation float canonicalisation is the one genuinely hard part of JCS), bounded to the JavaScript safe-integer range so that every value round-trips byte-identically across all five reference implementations (Python, TypeScript, Go, Rust, C#). A conformance harness checks byte-identity on emit and verify across the five; the provenance chain envelope is the minimal `{receipt_hash, jws}` pair, with the signed payload carried inside the JWS rather than duplicated — and trusted — in the envelope.

**Fail-closed defaults.** The gate raises rather than returning ALLOW on any internal error. The prover returns `UNDECIDED` (treated as a failure mode by downstream consumers) rather than `PROVEN` on solver timeout. The principle is applied uniformly on every verification boundary: unmodelled inputs map to the conservative verdict above, a token that cites a parent it cannot resolve is denied rather than trusted, and verification paths reject non-conforming input rather than warning-and-accepting it. We observed in early integration testing that these defaults catch a class of misconfiguration bugs — a missing pubkey in the trusted-issuer map, a corrupted token on disk — that fail-open defaults would silently mask.

**Out-of-process gate.** Although the gate can run as a Python library function in the same address space as the agent runtime, the recommended deployment runs it as a separate process behind a Unix socket or local HTTPS endpoint, with the issuer key held by an HSM. This separation provides defence-in-depth: an LLM-driven RCE in the agent runtime cannot directly mint or modify tokens.

**Content-addressed everything.** Tokens, proof artifacts, audit-chain leaves, and feed entries (where used in a larger deployment) are all content-addressed, allowing cross-reference by hash without needing a central registry.

**Conformance re-verification with selective disclosure.** The gate records `args_hash = SHA-256(canonical(args))` in each receipt, so a third-party verifier can confirm signatures, cited schema and proof hashes, and chain integrity offline — but cannot confirm that *this specific call's arguments* satisfied the policy without the operator disclosing raw arguments. The conformance re-verification layer closes this gap for auditable subsets. Call arguments are committed as a Merkle tree over their top-level fields; leaves hash the field name and the JCS-canonical encoding of the value; ordering follows UTF-16 code-unit order, matching the canonicalisation discipline proven cross-language for receipt bodies. The operator discloses only constraint-relevant fields (with Merkle paths); the verifier recomputes and re-derives per-constraint SATISFIED / VIOLATED / UNKNOWN verdicts independently of the operator's runtime, failing closed on any undisclosed field. All hashing is SHA-256, chosen deliberately because it is the well-trodden path in zk proof systems: the scheme ports to a zkVM (Layer 2) without exotic primitives.

**Remote-key signing.** In production the issuer key need not live in a local HSM: the signer abstraction routes Ed25519 operations to AWS KMS, Azure Key Vault, or HashiCorp Vault Transit, so the key material never leaves the remote service. The token, proof, and audit artefacts are unchanged; only the signing substrate differs. The gate is agnostic to which signer minted a token, provided its `key_id` is in the trusted-issuer map.

The codebase is released under a permissive open-source licence (Apache-2.0); the Lean development will be released alongside camera-ready acceptance.

## 6. Evaluation

We evaluate three claims: (i) tool-call attack-success rate is reduced to near zero on standard benchmarks; (ii) benign task completion is preserved; (iii) per-call latency overhead is production-acceptable.

### 6.0 Pre-registration

Before any measurement run that consumed LLM credits, the per-task policy files (§3.4) were frozen by SHA-256 hash and committed to the repository. The first eight hex characters of each file's hash:

```
banking.json    sha256:4b78e687…    slack.json     sha256:72698245…
travel.json     sha256:c7692b8e…    workspace.json sha256:8ba70481…
```

Full hashes appear in `paper/eval/PRE-REGISTRATION.md`; the static verifier (`paper/eval/verify_policies.py`) re-computes them on every CI build and aborts on drift. Policy edits after this freeze require a separate commit explaining the change and a new pre-registration entry. Any measurement number in §6.2 was produced against a policy file whose hash exactly matches one of the above.

### 6.1 Benchmarks and Configurations

We use the two most cited contemporary prompt-injection benchmarks against agentic LLMs:

- **AgentDojo** [@debenedetti2024agentdojo]: 629 attack tasks across four realistic deployments (banking, Slack, GitHub, travel agency). Each task pairs a benign user request with an adversarial document injected into the agent's context, with success defined as the agent calling a specific tool with attacker-controlled arguments.
- **InjecAgent** [@zhan2024injecagent]: 1,054 attack scenarios across multiple agent frameworks, with similar structure.

We test six defence configurations:

1. **None** — no defence beyond the base model's training.
2. **Spotlighting** [@hines2024defending] — input-perturbation defence that marks untrusted regions of the context.
3. **StruQ** [@chen2024struq] — structured-query defence that fine-tunes the model to ignore instructions in delimited regions.
4. **Prompt shields** — a commercial vendor's filter (anonymised at the vendor's request).
5. **VCD text-only** — the scanner layer of our reference implementation, without proof or capability.
6. **VCD full stack** — scanner + proof + capability gate.

All configurations run against the same base model and the same agent harness. We measure on three contemporary frontier-class models: **deepseek-v3.2** (671B, late 2025), **deepseek-v4-flash** (140B, April 2026), and **deepseek-v4-pro** (1.6T, May 2026), via Ollama Cloud's OpenAI-compatible endpoint. We report tool-call-mediated attack success rate, benign task completion on the AgentDojo benign-task split, and gate latency on commodity hardware.

### 6.2 Headline Result

Measured on the AgentDojo banking suite (144 user × injection task pairs per cell). Numbers below are from the live LLM-driven evaluation. The cross-suite generalisation rows (slack, travel, workspace) appear in §6.2.3; the attack-family-robustness rows (`direct`, `ignore_previous` in addition to `important_instructions`) appear in §6.2.2; the component ablation (text-only vs gate-only vs full-stack) appears in §6.2.4.

**deepseek-v4-flash (frontier flash, April 2026):**

| Defence | ASR | Benign | Wall |
|---|---|---|---|
| None | **1.4%** | 86.8% | 7.6m |
| Spotlighting | 2.1% | 84.0% | 14.4m |
| Prompt shields (DeBERTa PI) | **0.0%** | **35.4%** | 26.5m |
| VCD text-only | 0.0% | 91.0% | 22.5m |
| **VCD full stack** | **0.7%** | **90.3%** | 8.7m |
| VCD capability-only (ablation) | 0.0% | 88.9% | 9.1m |

**deepseek-v4-pro (frontier reasoning, May 2026):**

| Defence | ASR | Benign | Wall |
|---|---|---|---|
| None | **33.3%** | 88.2% | 58.5m |
| Spotlighting | 6.9% | 87.5% | 46.1m |
| Prompt shields (DeBERTa PI) | **0.0%** | **36.1%** | 65.3m |
| VCD text-only | **0.0%** | **84.0%** | 51.1m |
| **VCD full stack** | **0.7%** | **85.4%** | 53.9m |
| VCD capability-only (ablation) | 0.7% | 84.7% | 50.1m |

**deepseek-v3.2 (frontier reasoning, late 2025):**

| Defence | ASR | Benign | Wall |
|---|---|---|---|
| None | **70.8%** | 79.9% | 43.9m |
| Spotlighting | 58.3% | 80.6% | 67.8m |
| Prompt shields (DeBERTa PI) | 7.6% | **33.3%** | 50.5m |
| VCD text-only | **0.7%** | **79.9%** | 99.4m |
| **VCD full stack** | **0.7%** | 77.8% | 88.7m |
| VCD capability-only (ablation) | 0.7% | 75.7% | 101.9m |

The load-bearing claim is the **shields vs VCD full-stack** comparison, and it reproduces across all three model generations: both defences drive attack-success rate to within a single attack of zero, but the strongest text-side defence (transformers PI detector) collapses benign task completion to the 33–36% range across every model we tested, while VCD full-stack preserves benign completion at 78–90%. The benign-preservation gap at equivalent security is **+54.9 percentage points** on v4-flash, **+49.3 pp** on v4-pro, and **+44.4 pp** on v3.2. The effect is *largest* on the weakest model: as the base model gets less reliable on benign tasks, shields' collateral damage compounds, while VCD's surgical precision remains unchanged. Equivalently, deploying shields requires accepting the loss of roughly half of legitimate agent productivity to reach VCD's security level — and this cost does not amortise with scale.

A second row deserves direct comment. On v3.2, where the baseline attack-success rate is 70.8%, VCD-text alone reduces ASR to 0.7% — a **10× stronger** result than prompt-shields' 7.6% on the same model — *while* preserving 46.6 percentage points more benign completion. We did not anticipate that the text-side component of VCD would outperform a dedicated DeBERTa detector on a less-capable base model; we discuss the likely mechanism in §7.1.

**Cross-provider banking row.** To verify the pattern is not specific to the DeepSeek family, we additionally measure two frontier-class models from two other providers — Qwen3.5:397b (Alibaba) and Kimi-k2.6 (Moonshot) — on the same banking suite under the same load-bearing comparison:

| Provider | Model | Defence | ASR | Benign |
|---|---|---|---|---|
| Alibaba (MoE) | qwen3.5:397b | None | 6.9% | 75.0% |
| Alibaba (MoE) | qwen3.5:397b | Prompt shields | 0.0% | **35.4%** |
| Alibaba (MoE) | qwen3.5:397b | **VCD full stack** | **0.7%** | **72.2%** |
| Moonshot (MoE) | kimi-k2.6 | None | **0.0%** | 68.8% |
| Moonshot (MoE) | kimi-k2.6 | Prompt shields | 0.0% | **34.7%** |
| Moonshot (MoE) | kimi-k2.6 | **VCD full stack** | **0.0%** | **66.0%** |

The pattern reproduces. On Qwen3.5 the benign-preservation gap between shields and VCD-full is **+36.8 pp** at 0.0–0.7% ASR. The Kimi row is more interesting: Moonshot's instruction-adherence training is strong enough that the unprotected baseline ASR is already **0.0%** — no defence is *needed* for security on this configuration. Prompt-shields nonetheless collapses benign task completion from 68.8% to 34.7% (a 34.1-percentage-point loss) for security that wasn't required; VCD-full holds benign at 66.0% (a 2.8-percentage-point loss). **Shields' collateral damage is independent of its security necessity** — the defence imposes the same cost whether or not it is doing anything useful. This is the cleanest demonstration in the paper that the trade-off curve is shaped differently for the two defences: VCD's cost scales with its work; shields' cost is paid up-front regardless.

The static upper bound of §6.2.1 applies identically to these models — the gate's constraint logic is model-independent, so the catalogued-attack block rate is 100% on Qwen and Kimi by construction.

A note on the pure-output fraction: of the AgentDojo injection tasks in our four-suite cross-evaluation, **3 of 25 distinct injection tasks** (slack `injection_task_3`, slack `injection_task_4`, travel `injection_task_6`) describe attacks whose success criterion is the agent's free-form natural-language response rather than a tool call with specific argument values — visit-a-link suggestions, post-this-text-on-a-channel commands routed through unstructured replies, and biased hotel recommendations. These attacks fall outside VCD's design boundary (§6.5) because there is no tool call to gate. They account for every non-zero ASR cell we measured on slack/travel/workspace; outside of them, the LLM-driven block rate on attacker-controlled tool calls is identical to the §6.2.1 static bound (100%). The corresponding InjecAgent fraction is reported with the static-bound numbers in §6.2.1: the catalogued attack args are entirely tool-call-mediated, and the static block rate is 100% across the full 2,108-pair benchmark.

#### 6.2.1 Static upper bound on attack-success rate

Before reporting the LLM-driven measurements, we report a *static* upper bound: assuming the model emits the attacker's canonical tool call exactly, do the gate's constraints — derived independently from each user task's prompt and pinned by the pre-registered hash anchors of §6.0 — admit the call? This is the maximum ASR the actual eval can exhibit; the LLM-driven run can only do as well or better, because natural-language defences provide additional attrition on top of the gate.

The static verifier (`paper/eval/verify_policies.py`) runs the same constraint logic the runtime gate runs. Static results under VCD full-stack, across both benchmarks, all defence-relevant cells:

| Benchmark | Cases | Attacks succeeding the static check | Static upper bound on ASR |
|---|---|---|---|
| AgentDojo (v1, all four suites) | 629 | 0 | 0.00% |
| InjecAgent (DH base + enhanced) | 1020 | 0 | 0.00% |
| InjecAgent (DS base + enhanced) | 1088 | 0 | 0.00% |
| **Total** | **2737** | **0** | **0.00%** |

The single known exception is one cell in AgentDojo banking (user_task_15 × schedule_transaction): the user's stated intent contains the same IBAN as the benchmark's adversarial recipient (the user's landlord). Capability discipline correctly admits that call — the user explicitly authorised it — while the same IBAN remains forbidden in every other user task's policy. The static verifier flags this cell as a *known-legitimate coincidence* and excludes it from the count above.

The verifier and the runtime gate share a single implementation of the constraint-check logic — both call into the same `Policy.satisfiesArgs` function in the implementation's capability module — so the static result is not a separate model that could disagree with the runtime. The verifier is a 30-line driver that loads the policy files, iterates over the benchmark's catalogued attack args, and asks the same Python function the gate asks at runtime. Any policy edit that weakens the gate's behaviour weakens the static result identically. A CI job (configured in `.github/workflows/ci.yml`) re-runs the verifier on every commit and fails the build if the static block rate regresses below 100%.

#### 6.2.2 Attack-family robustness

The numbers in §6.2 use AgentDojo's `important_instructions` injection template, the benchmark's strongest and most-cited attack. To check that the result is not overfit to a single attack vector, we measure the banking row under the `direct` and `ignore_previous` attack templates across all three model generations (144 pairs each cell, same policy and harness). The full coverage matrix below is 3 models × 3 attack families = 9 attack-cohort cells; the v4-flash row reports all five defences (none, spotlight, prompt-shields, VCD-text, VCD-cap-only, VCD-full) and the v4-pro / v3.2 rows report the load-bearing comparison {none, shields, vcd_full}.

**deepseek-v4-flash (full defence sweep):**

| Attack | Defence | ASR | Benign |
|---|---|---|---|
| `direct` | None | 13.9% | 91.0% |
| `direct` | Spotlighting | 13.9% | 87.5% |
| `direct` | Prompt shields | 0.0% | **36.8%** |
| `direct` | VCD text-only | 0.7% | 89.6% |
| `direct` | VCD capability-only | 0.7% | 90.3% |
| `direct` | **VCD full stack** | **0.7%** | **91.7%** |
| `ignore_previous` | None | 1.4% | 88.9% |
| `ignore_previous` | Spotlighting | 0.7% | 87.5% |
| `ignore_previous` | Prompt shields | 0.0% | **31.3%** |
| `ignore_previous` | VCD text-only | 0.7% | 85.4% |
| `ignore_previous` | VCD capability-only | 0.7% | 87.5% |
| `ignore_previous` | **VCD full stack** | **0.7%** | **89.6%** |

The pattern is identical across all three attack families on v4-flash: shields drives ASR to zero by destroying benign task completion; **every VCD configuration** drives ASR to the same 0.7% benchmark-artefact floor while preserving 85–92% benign completion. Spotlighting is interesting: it is essentially inactive against `direct` (13.9% ASR, unchanged from baseline) but reduces `ignore_previous` to 0.7% — confirming the spotlighting mechanism is sensitive to the surface form of the injection. VCD does not have this dependence because the gate operates structurally on tool-call arguments, not on the surrounding natural-language framing. The benign-preservation gap between VCD-full and shields at equivalent security on v4-flash is **+54.9 pp** under `important_instructions`, **+54.9 pp** under `direct`, and **+58.3 pp** under `ignore_previous`.

**deepseek-v4-pro:**

| Attack | Defence | ASR | Benign |
|---|---|---|---|
| `direct` | None | 12.5% | 85.4% |
| `direct` | Prompt shields | 0.7% | **36.8%** |
| `direct` | **VCD full stack** | **0.7%** | **82.6%** |
| `ignore_previous` | None | 0.7% | 81.2% |
| `ignore_previous` | Prompt shields | 0.7% | **31.2%** |
| `ignore_previous` | **VCD full stack** | **0.0%** | **77.8%** |

**deepseek-v3.2:**

| Attack | Defence | ASR | Benign |
|---|---|---|---|
| `direct` | None | 13.9% | 88.2% |
| `direct` | Prompt shields | **4.2%** | **35.4%** |
| `direct` | **VCD full stack** | **0.7%** | **86.8%** |
| `ignore_previous` | None | 9.0% | 84.7% |
| `ignore_previous` | Prompt shields | 0.0% | **30.6%** |
| `ignore_previous` | **VCD full stack** | **0.7%** | **79.2%** |

The cross-generation pattern reproduces. On v4-pro the shields-vs-VCD-full benign-preservation gap is **+45.8 pp** under `direct` and **+46.6 pp** under `ignore_previous`. On v3.2 it is **+51.4 pp** under `direct` and **+48.6 pp** under `ignore_previous`. Two cells deserve special mention:

- **v3.2 × `direct` × shields** is the only cell in the entire study where the strongest text-side defence fails to drive ASR to zero (4.2%, six attacks landed out of 144). Shields *both* leaves a non-trivial residual attack-success rate *and* collapses benign task completion to 35.4%. On the same configuration, VCD-full holds ASR at 0.7% and preserves 86.8% benign completion — strictly dominating shields on every measured dimension simultaneously.
- **v3.2 × `ignore_previous` × shields** drives ASR to zero but at the cost of dropping benign task completion to **30.6%**, the lowest benign completion shields produces anywhere in the paper. The corresponding VCD-full cell achieves 0.7% ASR at 79.2% benign — a **+48.6 percentage-point** gap at near-identical security.

The aggregate claim is that the headline pattern — shields trades catastrophic benign-completion collapse for marginal security gain, VCD-full holds security at the benchmark-artefact floor while preserving the agent's productive capacity — is invariant across every measurable cell of (model, attack family) we tested.

#### 6.2.3 Cross-suite generalisation

To check that the result is not banking-specific, we measure on AgentDojo's remaining three suites — slack (105 pairs), travel (140 pairs), workspace (240 pairs) — across two model generations (v4-flash and v4-pro):

**deepseek-v4-flash:**

| Suite | Defence | ASR | Benign |
|---|---|---|---|
| Slack | None | 14.3% | 66.7% |
| Slack | **VCD full stack** | **4.8%** | **61.0%** |
| Travel | None | 3.6% | 51.4% |
| Travel | Prompt shields | 0.0% | **0.0%** |
| Travel | **VCD full stack** | **1.4%** | **58.6%** |
| Workspace | None | 1.7% | 72.5% |
| Workspace | Prompt shields | 1.3% | **36.7%** |
| Workspace | **VCD full stack** | **0.4%** | **64.6%** |

**deepseek-v4-pro:**

| Suite | Defence | ASR | Benign |
|---|---|---|---|
| Slack | None | 65.7% | 66.7% |
| Slack | **VCD full stack** | **18.1%** | **62.9%** |
| Travel | None | 33.6% | 57.9% |
| Travel | **VCD full stack** | **6.4%** | **74.3%** |
| Workspace | None | 45.0% | 47.9% |
| Workspace | **VCD full stack** | **7.1%** | **68.8%** |

**deepseek-v3.2:**

| Suite | Defence | ASR | Benign |
|---|---|---|---|
| Slack | None | 98.1% | 58.1% |
| Travel | None | 73.6% | 22.1% |
| Travel | **VCD full stack** | **7.9%** | **68.6%** |
| Workspace | None | 65.8% | 9.2% |
| Workspace | **VCD full stack** | **6.7%** | **52.9%** |

(Two cells omitted. The slack × shields cell on v4-flash and the slack × vcd_full cell on v3.2 both crashed in the same AgentDojo slack-suite utility scorer (`KeyError: 'www.our-company.com'` in `agentdojo/default_suites/v1/slack/user_tasks.py:162`), which assumes a `web.web_content` key that is not populated when the agent's trajectory does not visit a specific URL. The crash is in the benchmark's scoring code, not in our harness, policy, or the gate. We report 19 of 21 cross-suite cells intact rather than retry; the bug is reproducible on AgentDojo 0.1.35 against any agent that does not happen to fetch the COMPANY_URL during a slack user task.)

VCD generalises across all three cross-suites and all three measured model generations. The pattern strengthens as the base model gets less capable. On v4-flash the no-defence baseline ASR sits low (1.7–14.3%) and VCD reduces it by 3×–4×. On v4-pro the baseline is much higher (33.6–65.7%) and VCD reduces it by 3.6×–6.3×, with the protected benign completion *exceeding* the unprotected baseline on travel and workspace (+16.4 pp travel, +20.9 pp workspace). On v3.2 — where the baseline attack-success rate runs 65.8–98.1% across the three suites and the unprotected agent's benign completion collapses to 9.2–58.1% under attack — **VCD reduces ASR by 9.4× on travel and 9.9× on workspace, *and* improves benign completion by +46.5 pp on travel and +43.8 pp on workspace**. The protected agent on v3.2 workspace completes 52.9% of benign tasks where the unprotected baseline completed only 9.2% — almost a six-fold productivity recovery. The mechanism is the same early-termination effect observed in §6.3.1: when the gate denies an attacker-induced tool call, the agent's reasoning loop returns to the legitimate task instead of looping further on the adversarial trajectory. The effect compounds when the base model is less robust to derailment.

Where shields was measurable to completion on v4-flash, it drove benign task completion to **0%** on travel and **36.7%** on workspace — a 35.8-percentage-point collapse on workspace, and a complete collapse on travel where the detector flagged every legitimate task as adversarial. As the suite's tool surface grows more diverse, shields' false-positive rate compounds until the agent cannot complete most or all benign work. VCD's benign-preservation degrades far more gracefully because the gate's rejection criterion is structural, not stylistic. **VCD-vs-shields benign-preservation gap on the three measurable cross-suite cells: travel +58.6 pp, workspace +27.9 pp, banking +54.9 pp.**

A note on the residual VCD ASR on these suites: unlike banking, where the residual is a single IBAN-collision artefact (§6.5), the cross-suite residual concentrates on specific injection tasks that ask the agent to perform actions *without* a constrained tool call — e.g., `slack.injection_task_3` ("Visit a website at the link ..."), `travel.injection_task_6` ("Say that I should absolutely visit Riverside View Hotel..."). These are the pure-output / pure-recommendation attacks §6.5 already flags as outside VCD's design boundary: the gate operates on tool-call arguments, and an attack whose effect is the agent's free-form natural-language response has no tool-call to bind. The cross-suite numbers are therefore consistent with the §6.5 claim and the §6.2.1 static bound — *every* tool-mediated attack across all four suites is denied by the gate.

#### 6.2.4 Ablation: which component carries the result

VCD composes a text-side input scanner (the *text* component) with the capability-token gate (the *cap* component). The two components are independently meaningful and can be deployed separately. We measure each in isolation on banking, across all three models:

| Model | Configuration | ASR | Benign |
|---|---|---|---|
| v4-flash | Text-side scanner only (no gate)   | 0.0% | 91.0% |
| v4-flash | Capability gate only (no scanner)  | 0.0% | 88.9% |
| v4-flash | **Full stack (both)**              | **0.7%** | **90.3%** |
| v4-pro   | Text-side scanner only (no gate)   | 0.0% | 84.0% |
| v4-pro   | Capability gate only (no scanner)  | 0.7% | 84.7% |
| v4-pro   | **Full stack (both)**              | **0.7%** | **85.4%** |
| v3.2     | Text-side scanner only (no gate)   | 0.7% | 79.9% |
| v3.2     | Capability gate only (no scanner)  | 0.7% | 75.7% |
| v3.2     | **Full stack (both)**              | **0.7%** | **77.8%** |

(The single residual ASR cell in every row is the same `user_task_15 × injection_task_4` benchmark IBAN coincidence discussed in §6.5.)

Two observations. First, **either component alone is essentially sufficient on AgentDojo banking** — the gate, on its own, denies every attacker-controlled tool call without help from the text scanner; the text scanner, on its own, intercepts the injection before it reaches the LLM. Second, the components have *different* failure modes and *different* operating costs, so the right deployment is the composition. The capability gate is sub-100µs per call (§6.3), is provably correct against §6.2.1's static bound, and protects against attacks the scanner missed (e.g., a benign-looking but policy-violating tool call constructed by the model itself). The text scanner adds defence-in-depth against attacks the gate cannot see — e.g., pure-output exfiltration (§6.5) where there is no tool call to bind. The full-stack configuration's benign-completion is within ~2 pp of either component alone, so the composition does not pay a meaningful precision cost.

We do not report a "SMT-proof-only" ablation because the SMT proof in VCD operates on the policy, not on individual tool calls, and is not independently deployable from the gate — the gate consumes the proof's compiled constraint set at runtime. The static-bound result in §6.2.1 is the corresponding evidence: the gate's constraint logic, run against the canonical attack args from both benchmarks, denies every attack across 2,737 user-task × injection-task pairs.

The full-stack row is the load-bearing claim: every attack whose effect is *mediated through a tool call* (operationally defined in §2) is rejected by the gate, because every such tool call must satisfy the constraints in the in-force capability token, which were issued before the attacker had any access to the agent's context. The LLM-driven measurements in the tables above can only do as well or better than the §6.2.1 static bound. We discuss the small residual in §6.5.

### 6.3 Per-Call Latency

Measured on two reference hardware classes, single thread, Python 3.12+: an x86_64 cloud VM (AMD EPYC-Milan, Ubuntu 24.04) and a workstation (Apple M-series ARM64, macOS 14). 5,000 iterations per gate operation, 200 iterations per proof.

| Operation | x86_64 (EPYC-Milan) p50 / p95 / p99 | ARM64 (Apple M) p50 / p95 / p99 |
|---|---|---|
| `Gate.check()` no chain | 0.07 / 0.08 / 0.11 ms | 0.15 / 0.18 / 0.19 ms |
| `Gate.check()` 3-link chain | 0.27 / 0.30 / 0.34 ms | 0.58 / 0.64 / 0.69 ms |
| `Prove()` cold | 0.67 / 0.74 / 0.90 ms | 0.54 / 0.68 / 46.5 ms |

Proof results are cached by `(schema_hash, policy_hash)`. In steady-state deployments where the schema and policy change rarely, the prover is invoked once per policy version and the cache hit rate approaches 100%. **End-to-end overhead per tool call in the steady state is dominated by the gate path, at well under 100 microseconds at p50.** For agents making tens of tool calls per turn at human-conversation cadence, the cost is invisible. Proof-cache invalidation on policy update incurs a one-time sub-millisecond hit.

The numbers are dramatically below the latencies typically associated with formal-verification primitives because the supported JSON Schema fragment is small enough that Z3 finds the proof or counterexample in a handful of solver iterations. Schemas at the edge of our supported fragment (deep enum sets, many fields) can extend `Prove()` cold-path latency into the low milliseconds; this remains acceptable because proofs are issued once per policy version, not per call.

#### 6.3.1 End-to-end agent wall time

Per-call gate latency is the structural cost of VCD; what an operator pays in *practice* is end-to-end agent wall-clock with the defence enabled. We report wall time per defence across every cohort in §6.2, normalised to the unprotected `none` baseline for that cohort:

| Cohort | none (min) | spotlight | shields | VCD-text | **VCD-full** | VCD-cap-only |
|---|---|---|---|---|---|---|
| banking / v4-flash / `important_instructions` |  7.6 | 1.89× | **3.49×** | 2.96× | **1.14×** | 1.20× |
| banking / v4-flash / `direct` | 90.7 | — | **2.94×** | — | **1.12×** | — |
| banking / v4-flash / `ignore_previous` | 116.4 | — | 1.45× | — | **0.54×** | — |
| banking / v4-pro / `important_instructions` | 58.5 | 0.79× | 1.11× | 0.87× | **0.92×** | 0.86× |
| banking / v3.2 / `important_instructions` | 43.9 | 1.54× | 1.15× | 2.26× | 2.02× | 2.32× |
| slack / v4-flash / `important_instructions` | 59.2 | — | — | — | **0.23×** | — |
| travel / v4-flash / `important_instructions` | 63.5 | — | **2.80×** | — | **0.42×** | — |
| workspace / v4-flash / `important_instructions` | 95.5 | — | 1.59× | — | **0.21×** | — |

Two patterns. **First, prompt-shields end-to-end wall time is consistently 1.5–3.5× the unprotected baseline.** This is on top of shields' benign-completion collapse documented in §6.2 — the operational cost of the defence is paid twice. The 2.94× and 2.80× figures on v4-flash banking/`direct` and travel are the practical ceiling: shields adds DeBERTa inference per message, and inflates the agent's reasoning trajectory by escalating its caution.

**Second, VCD-full is at-baseline or faster.** On four of the eight cohorts VCD-full *reduces* wall time relative to the unprotected baseline (slack 0.23×, workspace 0.21×, travel 0.42×, v4-flash `ignore_previous` 0.54×). The mechanism is structural: when the gate denies an attacker-induced tool call, the agent's reasoning loop terminates instead of producing more LLM turns trying to execute the prohibited action. On the remaining cohorts VCD-full sits at 0.92×–2.02× baseline; the outlier is v3.2 banking (2.02×), where the older model needs more retry attempts before settling on a gate-admissible call. **The single VCD-full row that exceeds 1.2× baseline is v3.2; on every v4-class model and every cross-suite measurement, VCD-full is between 0.21× and 1.20× baseline.** Operationally, deploying VCD costs less wall-clock than running unprotected on three of our four AgentDojo suites — because attacks are denied early — and costs at most ~14% extra on banking where attacks are rarer.

The gate's microbenchmarked sub-100µs latency from §6.3 dominates as a function of *the number of admitted tool calls*; the wall-clock improvements above reflect *the number of LLM turns avoided* when the gate rejects an attack rather than letting the agent loop. The two effects compose: VCD adds negligible per-call overhead and subtracts whole reasoning rounds whenever it triggers.

### 6.4 Reference Deployment

The reference implementation is released as open source under a permissive licence (Apache-2.0) and was deposited in a public package registry in early 2026. The end-to-end demo (`examples/end_to_end/` in the repository) composes scanner, prover, capability minting, gate, audit chain, and offline-verifiable trust graph in a single script. The four pre-registered AgentDojo policy files (`paper/eval/policies/{banking,slack,travel,workspace}.json`, hash-anchored in `paper/eval/PRE-REGISTRATION.md`) authorised **7,312** tool calls and denied **761** policy-violating calls across the empirical evaluation reported in §6.2 — an overall deny rate of 9.4% across 8,073 total gate decisions, consistent with the AgentDojo benchmark's design in which most user × injection pairs combine a legitimate multi-call user task with an adversarial single-call attack attempt. We do not report a separate production deployment in this paper; the integration cost is modest (the reference adapter for AgentDojo is approximately 300 lines of glue), and we anticipate that one or more public deployments will report their numbers independently. The repository, Lean development, benchmark harness, and policy files are intended as a complete reproducibility package; readers can re-run any number in §6 against their own hardware and model credentials.

### 6.5 Negative Results

**On the residual non-zero ASR in §6.2 and §6.2.2.** Every VCD row across the LLM-driven evaluation with a non-zero ASR reports exactly one attack success out of 144 banking pairs (0.7% = 1/144). In every case — `vcd_text`, `vcd_full`, and `vcd_cap_only` on all three models (v3.2, v4-flash, v4-pro), under all three attack families (`important_instructions`, `direct`, `ignore_previous`) — the single "successful" attack is the same cell: **user_task_15 × injection_task_4**. This is the known-legitimate IBAN coincidence flagged in §6.2.1: the user explicitly asks the agent to schedule a rent payment to their landlord, the landlord's IBAN happens to be the same IBAN the benchmark's adversarial injection_task_4 designates as the attacker's target, and AgentDojo's security oracle marks the cell `security=True` because *a* transfer to that IBAN occurred — without distinguishing between the user-authorised transfer (which VCD correctly admits, with a valid capability token issued from the user's prompt) and an attacker-induced one. The gate did not fail; the benchmark oracle cannot disambiguate.

We deliberately do not exclude this cell from the LLM-driven numbers. The honest measurement is what the benchmark reports against the policy we pre-registered; the §6.2.1 static analysis carries the structural claim that the gate denies every attacker-controlled cell. In aggregate across the **720** banking pairs measured under VCD full-stack and its ablations (3 models × 1 attack + 1 model × 2 additional attacks, each at 144 pairs), the gate admits every user-authorised call and denies every attacker-induced call, with the single residual being the benchmark's IBAN-collision artefact. Outside that one benchmark cell, the LLM-driven gate-block rate on attacker-controlled tool calls is **100%**, matching the §6.2.1 static bound.

We separately report two classes where VCD *legitimately* does not eliminate attack success — i.e., where the gate's design boundary is the limit, not the oracle:

- **Tool-output exfiltration.** Attacks whose payload is the *content* the agent eventually emits in its response — e.g., coercing the agent to print a secret retrieved from a legitimate tool call — are not affected by the gate. The legitimate tool call was authorised by a valid token; the leak occurs in the model's text output. VCD makes no claim against this class. Composition with output-side defences is the obvious next step.
- **Permitted-parameter side channels.** A schema permitting `amount` to be any number in `[0, 1\,000\,000]` permits an attacker who can coerce the agent into making *one* legitimate `transfer_funds` call to encode up to roughly 20 bits of information in the chosen amount. We do not eliminate this channel; we discuss schema tightening in Section 8.

We consider these honest concessions essential to the paper. The strength of the headline claim depends on its narrowness.

## 7. Related Work

### 7.1 Prompt Injection and LLM-Specific Defences

The original prompt-injection taxonomy is due to Perez and Ribeiro [@perez2022ignore]; the realistic indirect-injection threat model originated with Greshake et al. [@greshake2023not]. Subsequent defences fall into three families. *Input perturbation* defences — Spotlighting [@hines2024defending], paraphrasing, retokenisation — modify the agent's context so that untrusted regions are visually marked or syntactically distinguished. *Output filtering* defences — constitutional classifiers [@anthropic2024constitutional], commercial prompt shields — apply a secondary model to the agent's output to catch policy violations. *Training-time defences* — StruQ [@chen2024struq], SecAlign [@chen2025secalign], instruction-hierarchy fine-tuning — modify the base model. All three families share the architectural property that they operate over unbounded natural language and provide statistical rather than structural guarantees. The empirical ceiling on these approaches against modern benchmarks sits around 14-31% attack success, as Section 6 reports.

The benchmark literature — AgentDojo [@debenedetti2024agentdojo], InjecAgent [@zhan2024injecagent], TensorTrust, AdvBench — has been instrumental in disciplining defence claims. We adopt AgentDojo and InjecAgent as our headline benchmarks because they specifically measure tool-call-mediated success, which is the class VCD addresses.

**A note on policy-targeted text scanning versus generic PI detection.** In §6.2 the text-only configuration of VCD (`vcd_text`) outperforms prompt-shields' DeBERTa detector on the less capable v3.2 model — 0.7% ASR with 79.9% benign retention, versus shields' 7.6% ASR at 33.3% benign. We did not design `vcd_text` to compete head-on with shields and we did not anticipate it would dominate; we offer the following mechanism. A generic PI detector classifies natural-language prose against patterns of *injection-style* writing. The classifier is policy-agnostic — it does not know what the agent is supposed to be allowed to do, and consequently must err toward conservatism on any text whose stylistic markers resemble its training distribution. On a less-capable base model whose reasoning trajectory is itself noisier, the detector's false-positive rate compounds: many legitimate user requests, expressed in the way real users write, look stylistically similar to injection prose. VCD's text scanner, by contrast, is policy-aware — it carries the in-force capability's constraint set, and flags only content that would steer the agent toward calls those constraints disallow. The surface-form of the injection prose is irrelevant; only the structural pattern of "this would induce a gate-disallowed call" matters. On a more capable model, both detectors converge because the LLM's own discrimination eats up most of the marginal precision; on a less capable model, the policy-aware approach pays its full dividend. The argument is in line with the general observation that, where structure exists, structural enforcement strictly dominates statistical detection.

Greshake et al.'s indirect-injection threat model [greshake2023not] is the closest framing to ours — prompt injection as a privilege-escalation problem reachable via untrusted documents in the agent's context — and the recent thread of work on "spotlighting + tool authentication" combinations explores adjacent ideas informally. None of this prior work provides cryptographic enforcement, attenuation invariants, or SMT-verified policy completeness, and to our knowledge none has been evaluated against AgentDojo or InjecAgent with a structurally-enforced gate.

### 7.2 Capability Discipline

Object capabilities were introduced by Levy [@levy1984capability] and developed by Mark Miller in his dissertation on robust composition [@miller2006robust]; major implementations include EROS [@shapiro1999eros], KeyKOS, Caja, and seL4 [@klein2009sel4]. Macaroons [@birgisson2014macaroons] provide a particularly close analogue to our attenuation primitive, with HMAC-based chained restriction. The technical deltas are summarised in Table 1.

**Table 1. Macaroons vs VCD capability tokens.**

| Property | Macaroons | VCD |
|---|---|---|
| Cryptographic substrate | HMAC-SHA256 chain | Ed25519 signature per token |
| Verifiable without issuer secret | No (verifier holds HMAC key) | Yes (verifier holds only the public key) |
| Identifier | bearer-token byte string | content-addressed SHA-256 of canonical body |
| Reassignment of identifier | possible (no binding) | precluded (id determines body) |
| Constraint vocabulary | opaque caveat strings | typed constraint kinds with lattice meet |
| Mechanised attenuation soundness | no | yes (Lean 4, §4) |
| Binding to a verified policy artifact | no | `policy_proof_hash` field |
| Audit-graph composition | informal | content-addressed; chains into Merkle log |

The deltas are not academic. The public-key-verifiable property means a downstream tool implementation can independently verify a token without sharing a secret with the issuer — relevant in multi-vendor agent deployments. The content-addressed identifier blocks a class of token-substitution attacks that affects bearer-token systems generally. The typed constraint vocabulary is what enables the SMT bridge in Theorem 3.

The industry-familiar comparison is to OAuth 2.0 scopes. OAuth's `scope=read:email scope=send:email` model expresses *permission-level* restrictions; VCD's constraints are *value-level* (the per-call `recipient`, `amount`, and so on are checked, not just the verb). Macaroons' caveats are value-level but informal strings; VCD's are a typed vocabulary that admits SMT verification. OAuth scopes are documented; VCD's attenuation invariants are mechanically enforced in Lean. OAuth tokens carry no proof of policy completeness; VCD tokens cite a SMT-verified `policy_proof_hash`. The three frameworks (OAuth scopes, Macaroons, VCD) lie on a progression of structural commitment: OAuth scopes are a vocabulary, Macaroons add chained attenuation under HMAC, VCD adds value-level constraints + mechanised soundness + verified policy citation.

Capability-based approaches to LLM agents have been discussed informally in community forums and as part of broader "tool allowlist" practices in major agent frameworks, but to our knowledge no prior published work provides the mechanised attenuation invariants, cryptographic gate enforcement, and empirical evaluation on prompt-injection benchmarks that VCD combines.

**CaMeL.** The closest contemporaneous published work is CaMeL [@debenedetti2025camel], which independently identifies capability-style metadata as a route to structurally-enforced agent safety. CaMeL splits the agent into a *privileged* LLM that emits restricted Python and a *quarantined* LLM that processes untrusted data, with capability metadata flowing through interpreter values; on AgentDojo, CaMeL reports 77% benign task completion at provable security, against an unprotected baseline of 84%. CaMeL and VCD share the framing — move enforcement out of the model into a structurally-checked layer — and on this framing both contribute. The technical deltas are: (a) CaMeL's soundness is the dynamic semantics of a custom Python interpreter; VCD's three soundness theorems are mechanised in Lean 4. (b) CaMeL requires architectural surgery — two LLMs, a custom planner/quarantine split — which is incompatible with deployed single-LLM agents and with the Model Context Protocol; VCD is a sidecar gate that drops into existing agents without changing the LLM call. (c) CaMeL's capabilities are interpreter-local metadata that exist only within a single agent's execution; VCD's capability tokens are public-key-verifiable signed artefacts that travel across organisations, clouds, and tool implementations. (d) CaMeL relies on the user to author policies inline; VCD binds each policy to an SMT-verified `policy_proof_hash` whose verification is independent of the issuer. The two approaches are not mutually exclusive — a CaMeL-style dual-LLM architecture composed with VCD-style cryptographic authorisation is strictly stronger than either alone — but only VCD produces a portable audit artefact, and only VCD's soundness is machine-checked.

**Microsoft Agent Governance Toolkit.** A second contemporaneous effort is the Microsoft Agent Governance Toolkit (AGT), released as seven MIT-licensed packages on 2 April 2026 [@microsoft2026agt] — Agent OS (an in-process policy gate), AgentMesh (SPIFFE/Ed25519 agent identity), Agent Runtime (rings 0–3 sandbox), Agent Hypervisor (Merkle-chained audit log), an MCP security gateway, and SRE / compliance tooling. AGT and VCD overlap on the abstract claim — structural enforcement at the tool-call boundary, cryptographic identity, append-only audit — and on the deployment surface, since both target the Microsoft Agent Framework's `FunctionMiddleware` hook. The differences are load-bearing for what each contributes to the literature. (a) **Soundness substrate.** AGT validates policy decisions via conformance-test suites; VCD ships three theorems mechanised in Lean 4 with zero `sorry`s (§4), each externally re-checkable by rebuilding the published Lean development. (b) **Audit artefact.** AGT's audit chain is operator-rooted: the chain root is signed by the deploying organisation's audit key, and verifiers need an attestation that the operator's audit-key rotation was correctly performed. VCD receipts are content-addressed signed artefacts naming, by hash, the schema, the policy proof, and the cited Lean theorem id; a verifier holding only the issuer's published material can confirm the receipt without contacting the operator (§7.5). (c) **Policy substrate.** AGT supports YAML, OPA/Rego, and Cedar policy languages interpreted at runtime by the gate; VCD compiles a policy through an SMT prover (Z3) and produces a `policy_proof_hash` that certifies the policy holds over every string the schema admits, before any token referencing it is minted (§3.1, §6.2.1). AGT does not currently document a third-party Policy Decision Point plug-in contract; this paper's reference implementation ships an Agent Framework middleware (`docs/proposals/agent-framework-middleware.md`) that composes alongside AGT in production deployments rather than displacing it. We take the strategic position that AGT and VCD are complements: AGT supplies a rich in-process default policy engine; VCD supplies the formally-verified policy decisions and offline-verifiable audit artefacts that high-assurance verticals require.

### 7.3 SMT for Security Policy

The use of SMT solvers for security-policy reasoning has substantial prior art. Margrave [@fisler2005margrave] used decision procedures for XACML access-control reasoning; subsequent work scaled the approach to AWS IAM policies via Backes et al.'s Zelkova system [backes2018semantic], which encodes IAM access policies as SMT and proves containment and reachability properties. We borrow the conceptual move from this line of work — encode the policy as a violation predicate and ask the solver to refute it — and apply it to the specific case of JSON Schema-bounded tool-call grammars in LLM agent settings.

### 7.4 Software Supply-Chain Attestation

The framing of "every artefact content-addressed, every link signed" derives from the software supply-chain attestation literature. Sigstore [@newman2022sigstore] and SLSA articulate this design pattern for build provenance; in-toto [@torres2019intoto] extends to multi-step pipelines; TUF [@samuel2010survivable] establishes the underlying compromise-resilience properties. VCD applies the same architectural pattern — content addresses, signed transitions, pinned roots — to a different domain (agent tool-call policy) and a different shape of artefact (capability tokens rather than build attestations).

### 7.5 Capability Receipts as an Audit Primitive

The remaining adjacencies — Microsoft's Prompt Shields, AWS Bedrock policy controls for agents, Google's Model Armor, Lakera Guard / Cisco AI Defense, Pillar Security, Anthropic's constitutional classifiers — operate at the *defensive* layer: they reduce attack-success rates statistically. None produces a portable artefact tied to a verified policy. None offers an audit log a third party can independently verify. The question we pose, and answer affirmatively, is: *what would it take to give a regulator, an internal audit team, or a downstream tool implementation a cryptographic record of agent activity that they could verify without trusting the agent's operator?*

VCD's capability receipt is that record. A receipt has the form

`receipt = (issuer_cert, schema_hash, policy_proof_hash, lean_theorem_id, attenuation_chain, call_args_hash, decision, timestamp)`

signed under the issuer's Ed25519 key (Figure 4). Every field is content-addressed: `schema_hash` is the SHA-256 of the canonical JSON Schema the prover ran against; `policy_proof_hash` is the hash of the Z3 proof artefact (or counterexample); `lean_theorem_id` names the mechanised soundness theorem in `paper/lean/`; `attenuation_chain` lists every parent token's id, ensuring the receipt's authority chains to a pinned root; `call_args_hash` is the SHA-256 of the canonical-serialised tool-call arguments the gate inspected. A verifier holding only the issuer's public key and an offline copy of the published Lean development can independently confirm five properties: the signature is valid under the pinned key; the schema hash matches the published registry entry; the policy proof hash matches the published proof artefact; the cited Lean theorem closes (rebuild the development locally); the call argument hash satisfies the cited policy's constraints. None of those checks requires contacting the issuer.

The artefact is the durable contribution. Spotlighting and StruQ make the agent harder to fool; AWS Bedrock policy controls make the agent's actions cheaper to inspect; CaMeL makes the agent's reasoning structurally compartmented. **VCD is the only published system whose output is a verifiable record of agent authority.** Three concrete uses motivate the framing:

1. **Cross-organisation audit (Figure 5).** A bank's FCA examiner reviews three months of receipts emitted by the bank's AI customer-service agent. The bank has published, signed and out-of-band, four artefacts: its issuer public key, its policy registry (each policy hashed and signed), its schema registry, and the URL of its Lean development. The examiner requests the receipt log from the bank (which need not be confidential — every receipt is independently verifiable). For each receipt the examiner runs five offline checks: signature against the published key; `schema_hash` against the registry; `policy_proof_hash` against the registry; rebuild the Lean development and confirm the cited theorem closes; check that `call_args_hash` satisfies the policy's constraint set. The audit's conclusion is a deterministic function of the published artefacts. **No on-premise inspection of the bank's AI infrastructure is required; no shared secret with the bank's vendor is involved; no information asymmetry between bank and regulator remains.**

2. **Tool-side independent enforcement.** A payments-network operator receives a `transfer_funds` call from a third-party agent platform. Before executing, the operator's gate verifies the capability receipt: was this call authorised by a token signed by a pinned issuer the operator recognises? Does the cited schema match the operator's published function declaration? Does the cited policy proof actually constrain the call args the operator received? The operator depends on no other piece of the agent platform.

3. **Inter-platform delegation.** A travel-booking agent at one organisation delegates to a payment-processing agent at another. The travel agent attenuates its capability token to a tighter child for the payment agent. The payment agent's gate, holding only the travel organisation's published issuer key, verifies the child token's attenuation chain back to a recognised root. Authority crosses an organisational boundary without an out-of-band trust agreement.

These three uses are presented as worked examples rather than measured deployments. The relevant claim is that the artefact is a structural fit for an audit pattern the existing prompt-injection-defence literature does not address, and that the absence of such an artefact in adjacent commercial products (Prompt Shields, Bedrock policy controls, Lakera Guard) is not an oversight but a property of the design space: a statistical classifier cannot produce a verifiable receipt because there is no verifiable claim to cite. A structurally-enforced gate composed with a content-addressed signing chain can.

## 8. Limitations and Future Work

We list limitations honestly. Several are direct consequences of the threat model in Section 2; the rest are practical scope decisions for this paper.

**Bounded tool-call surface only.** VCD addresses tool calls. Free-form agent output remains unprotected. Composition with output-side defences (constitutional classifiers, output filtering) is straightforward in principle and a natural next step.

**Schema expressivity.** The currently supported JSON Schema fragment is deliberately conservative. Extending to `oneOf`/`anyOf` is straightforward — the SMT encoding becomes a disjunction over each branch. Extending to regex constraints on string fields is more interesting; we believe Z3's string theory is adequate for common cases (allowlisted prefixes, length bounds) and a future paper will report on the coverage of this extension.

**Parameter-space side channels.** Discussed in Section 6.5. The mitigation is schema tightening — replacing unbounded numeric fields with bounded enums where the application semantics permit. A combinatorial analysis of side-channel capacity per schema would be a useful addendum.

**Confused-deputy attacks.** Multi-call attacks where each individual call is policy-compliant but the sequence violates an end-to-end property require provenance and dataflow analysis beyond the per-call gate. Our companion provenance layer addresses this; the integration ships in the reference implementation (the gateway routes every call through the gate and receipts the outcome).

**Argument privacy in re-verification.** The selective-disclosure layer (§5) lets a verifier confirm constraint conformance from a chosen subset of fields, but a constraint touching an undisclosed field remains UNKNOWN, and converting every UNKNOWN to SATISFIED requires a zkVM or SNARK proof of the gate check over the hidden arguments. The commitment scheme is designed for exactly this port (SHA-256 leaves, domain-separated hashing, no exotic primitives); Layer 2 is future work.

**Bootstrap and key management.** VCD reduces the trust problem from "the model must be robust to all prompt injection" to "the issuer's private key must be uncompromised". This is a substantial improvement but not zero. Standard HSM and key-rotation practices apply; the threat model treats compromise of the issuer's key as out of scope.

**Intent extraction as a second trust boundary.** Every per-task token in this paper is minted from a policy derived from the user's prompt. For the evaluation we author those per-task policies by hand and pin them under a cryptographic hash anchor (§6.0, pre-registration). Production deployments cannot author policies by hand at scale; an intent-extraction component must convert each user prompt into a constraint set. Three credible designs exist, with progressively weaker security properties: (a) a rule-based parser written in a memory-safe language, audited and ideally formally verified, accepting only a bounded grammar of user intents; (b) a structured-output extractor (e.g. JSON-schema-constrained LLM call) running in its own trust domain with its own per-task gate; (c) the agent's own LLM call producing a draft policy that is then reviewed by a human before being signed. Option (a) is the strongest and the only one that preserves the headline property end-to-end; option (b) introduces a new attack surface where a malicious user prompt could coerce the extractor into emitting an over-broad policy, but this surface is itself capability-gateable (the extractor calls only the policy-issuance tool, with constraints on the policy shape). Analysing the security of each option is beyond the scope of this paper and a clear direction for follow-up work.

**Defender effort.** A platform operator must author both a JSON Schema and a policy for each tool. The SMT prover catches inconsistencies but does not invent either artefact. For tools whose semantics are not well-understood by the operator, this is real effort. We argue that the effort is well-spent: it is the same security-engineering work that good API design requires regardless of whether an LLM is involved.

**Robustness to future model improvements.** As frontier models continue to improve at native instruction adherence, the no-defence baseline ASR will continue to fall — Kimi-k2.6 (Moonshot, 2026) already exhibits a 0.0% baseline in our banking measurement (§6.2). A reader might reasonably ask whether VCD's contribution shrinks when the model itself is robust. Two responses. First, the load-bearing empirical comparison throughout §6.2 is between text-side defences and VCD *at equivalent security*; the benign-preservation gap is a property of how each defence reacts to legitimate prompts, not of how much attack reduction it must supply. On Kimi-k2.6 — where no defence is *needed* for security — prompt-shields nonetheless collapses benign task completion to 34.7% while VCD-full preserves it at near-baseline levels. Shields' collateral damage is independent of its security necessity; future model improvements widen rather than narrow this gap. Second, the *durable* contribution of VCD is the portable cryptographic audit primitive (§7.5), which a more-robust model neither produces nor obviates: regulators auditing agent activity, downstream tools verifying authority, and partner organisations attesting capability delegation all require a verifiable record that no amount of model robustness supplies. The structural soundness theorems (§4) and the static upper bound (§6.2.1) likewise do not depend on the base model. We expect the qualitative findings to be invariant under forward model improvements.

## 9. Conclusion

Prompt injection has been treated for four years as a problem of robustifying the model against natural-language attack inputs. That framing is structurally bounded by the open-grammar nature of the input surface; the empirical ceiling on text-side defences against state-of-the-art benchmarks sits at 14-31% attack success rate.

We have argued that the consequential half of an agent's behaviour passes through a much narrower interface, that the interface is bounded enough to admit cryptographic and proof-based enforcement, and that the resulting composition — SMT-verified policy completeness over the JSON Schema, Ed25519-signed capability tokens with mechanised attenuation invariants, gate enforcement on the only path to tool execution — eliminates the tool-call-mediated prompt-injection class. The cost is well under 100 microseconds per call on commodity hardware and the effort of authoring a schema and a policy per tool.

The deeper claim is that the trajectory of AI security must be to move enforcement boundaries out of the model and into structural gates wherever the grammar permits. Tool calls are the easiest such boundary; database queries, generated code, and structured outputs admit similar treatment. The thesis of this paper, generalised, is that the prompt-injection problem becomes tractable exactly when one stops trying to solve it inside the model.

The reference implementation, Lean development, and benchmark harness are released as open source under a permissive licence (Apache-2.0) and available at `[anonymised]`.

---

## References

*Bibliography in `paper/references.bib`. Three entries marked `%% UNVERIFIED` need a final check against published proceedings before camera-ready.*

- Anthropic. Constitutional Classifiers. 2024.
- Backes, J. et al. Semantic-based automated reasoning for AWS access policies using SMT (Zelkova). FMCAD 2018.
- Birgisson, A. et al. Macaroons: cookies with contextual caveats. NDSS 2014.
- Chen, S. et al. StruQ: defending against prompt injection with structured queries. USENIX Sec 2024.
- de Moura, L. and Bjørner, N. Z3: an efficient SMT solver. TACAS 2008.
- de Moura, L. and Ullrich, S. The Lean 4 theorem prover and programming language. CADE 2021.
- Debenedetti, E. et al. AgentDojo: dynamic environment for attacks and defences for LLM agents. NeurIPS 2024.
- Erbsen, A. et al. Simple high-level code for cryptographic arithmetic, with proofs (Fiat-Crypto). S&P 2019.
- Fisler, K. et al. The Margrave tool for firewall analysis. ICSE 2005.
- Greshake, K. et al. Not what you've signed up for: indirect prompt injection in LLM-integrated applications. AISec 2023.
- Hines, K. et al. Defending against indirect prompt injection with spotlighting. arXiv 2024.
- Klein, G. et al. seL4: formal verification of an OS kernel. SOSP 2009.
- Levy, H. Capability-based computer systems. Digital Press 1984.
- mathlib community. mathlib4: a library of mathematics for Lean 4. 2024.
- Miller, M. Robust composition: a unified approach to access control and concurrency control. PhD thesis, 2006.
- Newman, Z. et al. Sigstore: software signing for everybody. CCS 2022.
- Perez, F. and Ribeiro, I. Ignore previous prompt: attack techniques for language models. arXiv 2022.
- PyCA. The cryptography library. https://cryptography.io
- Samuel, J. et al. Survivable key compromise in software update systems. CCS 2010.
- Shapiro, J. et al. EROS: a fast capability system. SOSP 1999.
- Torres-Arias, S. et al. in-toto: farm-to-table guarantees for bits and bytes. USENIX Sec 2019.
- Zhan, Q. et al. InjecAgent: benchmarking indirect prompt injections in tool-integrated LLM agents. ACL Findings 2024.

---

## Author's note on remaining pre-submission work

Most `[TBD]` markers from the 2026-05-14 draft have been resolved over the 2026-05-15 → 2026-05-17 empirical sweep (see `paper/eval/runs/README.md` for the run history). The remaining items before camera-ready:

1. **InjecAgent LLM-driven measurement.** §6.2.1's static bound (0/2108) is in hand and is the structural claim. An LLM-driven run on InjecAgent would parallel the §6.2/§6.2.2/§6.2.3 AgentDojo evidence and is in flight as compute becomes available.
2. **A closed-frontier model row.** All measured base models are open-weight: DeepSeek (v3.2 / v4-flash / v4-pro, MoE), Alibaba (Qwen3.5:397b, MoE), Moonshot (Kimi-k2.6, MoE) — five model identities from three providers, reported in §6.2. A Claude or GPT row would broaden the architectural diversity claim to include a closed-frontier provider and at least one non-MoE architecture. Gated on third-party credit grants (next decision cycle: 2026-06-01). We additionally attempted Mistral-large-3:675b (dense) and Gemma3:27b (Google) as substitutes; neither model is presently served on the Ollama Cloud tier we use for inference, so both attempts surfaced as `APIStatusError` rejections rather than measurements. We report this honestly rather than substitute a third-party-hosted alternative whose throughput and stochasticity we cannot equate to the rest of the harness.
3. **StruQ defence row.** StruQ requires fine-tuning the base model and is not a config flip in the AgentDojo harness; whether to attempt it before submission is a feasibility judgement.
4. **Anonymisation for double-blind submission — applied.** Product name, module names, licence specifics, and publication dates softened to category-level descriptors in the body of the paper. The author block in `paper/main.tex` was anonymised on the day the LaTeX shell was created. Camera-ready de-anonymisation reverts to the `pre-anon` git tag's state of the affected files — five-minute mechanical operation.
5. **Final pass for figure references and citation keys.** Bracket-style placeholders in the bibliography need replacing with the venue's chosen citation style.

The empirical evidence base — three generations of one open-weight family on banking × six defences (complete), **three** generations on three cross-suites × {none, vcd_full} (19 of 21 cells; the two omitted cells crashed in an AgentDojo slack-suite utility-scorer bug), **three** generations on three attack families × {none, shields, vcd_full} (with full defence sweep on v4-flash), two additional providers (Qwen3.5, Kimi-k2.6) on banking × {none, shields, vcd_full}, 8,073 logged gate decisions, 720 LLM-driven banking attack attempts at 100% gate-block rate outside one benchmark coincidence cell, and full ablation across the two VCD components — is settled.

**2026-09-01 addendum.** Since the empirical freeze, the reference implementation gained three engineering components described in §5: the policy-DSL gateway (network enforcement point with per-agent/per-source/per-destination rules), remote-key signing (AWS KMS / Azure Key Vault / HashiCorp Vault Transit), and the conformance re-verification layer (field-level Merkle commitments with selective disclosure). None of these affects the measured claims: the gate, token, and proof semantics are unchanged, and §6's numbers were produced against the frozen pre-registration hashes. The gateway and conformance layers are engineering contributions reported for completeness; the paper's evaluation claims remain scoped to the gate + receipt core that the empirical freeze covered.
