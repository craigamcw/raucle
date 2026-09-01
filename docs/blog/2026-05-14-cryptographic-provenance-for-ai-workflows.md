# Cryptographic Provenance for AI Workflows — A Draft Standard

*Published 14 May 2026 · Raucle Engineering · Spec: [raucle.com/spec/provenance/v1](https://raucle.com/spec/provenance/v1)*

---

Picture a Monday morning. A regulator has questions about a decision your AI made last quarter. A customer is in court because an AI-generated contract clause cost them money. A journalist wants to know which model produced a public-facing summary that turned out to be wrong. In every case, you need to answer the same set of questions:

- Which model produced this output?
- Which agent invoked the model?
- What was in the context window when it decided?
- Did any of that come from untrusted sources?
- Were the guardrails actually active?
- Has any of this been altered since?

If your AI stack looks like most stacks in 2026, you cannot answer **any** of them with cryptographic certainty. You have logs, but logs are claims, not evidence. You have screenshots, but screenshots aren't signed. You have a vendor's word, but the vendor's word does not survive cross-examination.

This is the gap I want to talk about.

## Software supply chain figured this out. AI hasn't.

Five years ago you had the same problem for software artifacts. *"Did this binary actually come from the source code you say it did? Was it built on the infrastructure you say it was? Has it been tampered with since?"* The answer was usually a shrug.

Then the industry did three things, in order:

1. **It standardised an attestation format.** [in-toto](https://in-toto.io/) defined how to describe what happened during a build, with sufficient structure that a third party could re-derive trust without contacting the builder.
2. **It built signing infrastructure.** [Sigstore](https://www.sigstore.dev/) wrapped that format in keys, certificate transparency, and Rekor's append-only log.
3. **It got the major ecosystems to integrate.** PyPI, npm, Maven, Docker, GitHub, and Linux distros now produce and verify these attestations natively. The format won not because it was clever — it won because everyone targeted it.

The result: today, you can ask a hard provenance question about a build artifact and *get a hard answer*. Bill of materials, build platform, transparency log entry, signature. All cryptographic. All re-verifiable years later by anyone with a public key.

AI inference, agentic workflows, and tool-mediated LLM applications have **none of this**. Every guardrail vendor scores prompts. None sign their decisions. Every audit log records what an LLM was asked. None prove the LLM actually got that input. Every system promises a guardrail ran. None prove the verdict came from the guardrail.

That's the gap. This post is about closing it.

## Introducing the Raucle Provenance Receipt v1

We've published a draft normative specification at [raucle.com/spec/provenance/v1](https://raucle.com/spec/provenance/v1) for a compact, cryptographically signed envelope that records a single step in any LLM workflow. We call it a **provenance receipt**.

Receipts compose. Each one cites its parents — the receipts representing the work that fed into it. Receipts form a Merkle DAG. Given any output, a verifier can walk back through the chain to the original user input and confirm, with Ed25519 mathematics, that nothing in the lineage has been altered.

Every receipt records one of eight operation types — `user_input`, `model_call`, `tool_call`, `retrieval`, `guardrail_scan`, `agent_handoff`, `sanitisation`, or `merge` — plus the inputs and outputs (as hashes; receipts never carry the raw text), the model or tool involved, and a taint set tracking the provenance of untrusted data through the workflow. The whole thing is a compact JWS (`alg=EdDSA`, `typ=provenance-receipt/v1`), so any system that handles JSON can store, transport, and verify them.

## In 30 lines of code

Here is what it looks like when you actually use it:

```python
from raucle import AgentIdentity, ProvenanceLogger, Scanner

# Once at deploy time
identity = AgentIdentity.generate(
    agent_id="agent:customer-support",
    allowed_models=["claude-sonnet-4-6"],
    allowed_tools=["lookup_order", "send_email"],
    ttl_seconds=365 * 24 * 60 * 60,
)

# At runtime, per request
with ProvenanceLogger(agent=identity, sink_path="audit/provenance.jsonl") as log:
    scanner = Scanner(provenance_logger=log)

    root = log.record_user_input(user_message, taint={"external_user"})

    scan = scanner.scan(user_message, provenance_parents=[root])
    if scan.action == "BLOCK":
        return refuse(scan)

    model_step = log.record_model_call(
        parents=[scan.provenance_hash],
        model="claude-sonnet-4-6",
        input_text=user_message,
        output_text=response,
    )

    log.record_tool_call(
        parents=[model_step],
        tool="send_email",
        input_args={"to": "...", "body": response},
        output={"id": "msg_1"},
    )
```

Twelve hours later, when something goes wrong and someone asks "did the guardrail actually run before this email was sent?", the answer is a single command:

```
$ raucle provenance trace sha256:<send_email_receipt_hash> --chain audit/provenance.jsonl
```

The trace walks the DAG backwards through `send_email` → `model_call` → `guardrail_scan` → `user_input`, and a verifier with the agent's public key can cryptographically confirm every step. The guardrail's verdict is signed. The model invocation is signed. The user input's taint propagates monotonically through the chain. If any record was modified between then and now, verification fails.

## Four reference implementations, byte-for-byte conformant

A spec without implementations is a wish. Today, alongside the spec, we are publishing four reference implementations, all MIT-licensed, all available on GitHub:

| Language | Repo | Dependencies |
|---|---|---|
| **Python** | [epic28-ltd/raucle](https://github.com/epic28-ltd/raucle) | one — `cryptography` |
| **TypeScript** | [epic28-ltd/raucle-receipt-ts](https://github.com/epic28-ltd/raucle-receipt-ts) | **zero** — Node's `node:crypto` |
| **Go** | [epic28-ltd/raucle-receipt-go](https://github.com/epic28-ltd/raucle-receipt-go) | **zero** — stdlib only |
| **Rust** | [epic28-ltd/raucle-receipt-rs](https://github.com/epic28-ltd/raucle-receipt-rs) | RustCrypto primitives only |

All four ship the same JSON test-vector file in their CI. Every implementation must reproduce every published vector byte-for-byte — both the JWS string and the SHA-256 of that string — and every implementation must successfully verify every published signature. If any implementation drifts from the spec, CI fails on the next push.

This is the difference between a protocol and a library. A protocol is something other people target. The four-language conformance contract is what makes the receipt format actually targetable.

## What we explicitly did not solve

A draft standard is also a list of things we are *not* claiming to fix. Three are worth naming out loud:

**We do not prove the model actually saw what the receipt says it saw.** A compromised agent could record one input hash and pass a different prompt to the LLM. Closing this gap requires hardware-attested inference — TEE-style confidential compute or zero-knowledge proofs of model execution. The receipt format is a substrate that future TEE extensions can layer on top of. v1 establishes the substrate.

**We do not encrypt receipts.** They are signed but not confidential. Transport-layer and storage-layer encryption is the deploying party's responsibility. We deliberately kept the wire format inspectable so that humans can read it during incident response — encryption can be layered without changing the signed envelope.

**We do not specify revocation transparency.** If an agent's private key is compromised, today you rotate it and stop trusting receipts after a date. A formal revocation log — analogous to Sigstore's Rekor — is the obvious v2 extension. We did not want to ship that before getting protocol feedback on v1.

## Where this is heading

Three things in the next quarter.

**A formal contribution to OWASP AI Exchange and a feedback issue against the NIST AI RMF.** The format needs to live inside the standards-body ecosystem, not adjacent to it. We will be writing to both.

**Talk submissions.** RSA Innovation Sandbox, BlackHat AI Summit, OWASP AI Summit, AI Village at Defcon. The protocol-vs-library distinction matters and benefits from being argued in front of practitioners.

**The next reference implementations.** Java, Swift, and C# are the obvious gaps for enterprise adoption. We will write Java ourselves; we are hoping community implementers pick up Swift and C# (please get in touch if you would like to take one).

We are also publishing a tool-poisoning detector for MCP server manifests, a confidential-compute extension proposal that binds receipts to TEE attestation quotes, and a counterfactual-replay command that lets SOC teams ask "if I had had stricter rules on, would this attack have landed?" — all in the same release cycle. Provenance is the foundation those features ride on.

## What you can do today

Three things, in increasing order of commitment.

**Read the spec.** [raucle.com/spec/provenance/v1](https://raucle.com/spec/provenance/v1) is short — about 500 lines of normative Markdown — and the test vectors are five entries you can re-derive yourself if you want to satisfy the cryptographer in you.

**Try one of the implementations.** `pip install raucle`, `npm install @raucle/receipt`, `go get github.com/epic28-ltd/raucle-receipt-go`, or `cargo add raucle-receipt`. The "hello, world" is twenty lines. The audit chain it produces is real, signed, and verifiable.

**File an issue on the spec.** We would much rather hear "this is wrong because…" today than ship v1 final and have to publish v2 next year. Issues tagged `spec` get a 14-day public-comment treatment before any change merges.

There is exactly one moment when a draft standard becomes a real standard, and that moment is when the second independent project decides to target it. Today we are giving you four reference implementations and an invitation. If you are building agentic systems, RAG pipelines, or LLM-mediated automation, you already have a provenance problem — whether you have admitted it to yourself yet or not. The receipt format is one way to start admitting it.

Verifiable AI is not going to arrive because vendors get more honest. It is going to arrive because the protocols make honesty cheap and dishonesty detectable. We would like that arrival to be sooner rather than later.

---

*Discussion: [Hacker News](#) · [Lobste.rs](#) · [/r/MachineLearning](#) · [OWASP AI Exchange](#) · [GitHub Issues](https://github.com/epic28-ltd/raucle/issues?q=label%3Aspec)*

*Raucle is an open-source AI security project. The runtime detection engine, the provenance receipt format, and all four reference implementations are MIT-licensed.*
