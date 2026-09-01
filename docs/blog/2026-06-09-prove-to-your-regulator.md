# How to Prove to Your Regulator What Your Agent Did — Without Trusting Your Cloud Provider

*Published 9 June 2026 · Raucle Engineering · Release: [raucle v0.19.0](https://github.com/epic28-ltd/raucle)*

---

Picture the meeting you are eventually going to have. An examiner from the FCA — or BaFin, or MAS — is sitting across the table. Your firm has an AI agent in production: it reads customer records, moves money between ledgers, calls internal tools. The examiner asks the question that decides the audit:

> *"Show me what this agent did on the 3rd of March, and prove it couldn't have done anything you didn't authorise."*

You have spent your career answering exactly this kind of question for payments systems and trading platforms. You know what a passing answer looks like, and you know what a failing one looks like. So you also know the uncomfortable truth about most AI-agent deployments today: **the honest answer is a pile of application logs and a request that the examiner trust them.**

That is not how the rest of your regulated estate works. Nobody asks an examiner to trust the application's own logs for a wire transfer. The evidence is signed, independently verifiable, and survives the failure or hostility of any single component. AI agents should be held to the standard regulated industries already demand for everything else. This post is about how to get there — and why the obvious answer from your cloud provider does not.

## The cloud-provider answer, and why it fails the audit

In March 2026, AWS shipped **Bedrock AgentCore Policy** (GA). It is a genuinely good feature: it treats the agent as an untrusted actor, intercepts every tool call, evaluates it against a Cedar policy *before* the call reaches a tool, and logs every decision to CloudWatch. If you only needed to answer *"did we gate the agent's actions?"*, this would be most of the way there.

But re-read the examiner's question. They did not ask whether *you* gated the agent. They asked you to **prove** what happened. And the evidence AgentCore produces is a CloudWatch log — which is to say, **the cloud provider attesting to its own behaviour, readable only by trusting the cloud provider.**

That is a category error for a regulated firm. You cannot discharge an audit obligation by saying *"Amazon's logs say so."* The examiner's whole job is to not take any single party's word for it — including yours, and including your vendor's. Evidence that is only verifiable by trusting the system that produced it is not evidence in the sense an auditor means. It is a vendor-locked, single-cloud record that disappears the day you change providers and that no third party can independently check.

The gap is not gating. AWS gates fine. The gap is **portable, independently verifiable proof.**

## What "provable" actually means here

raucle takes a different shape. The agent never holds the downstream credential. A small **custody gate** holds it, and is the only thing that can sign and forward a call — so *no receipt, no action* is a structural fact, not a policy: the agent literally cannot act, because it holds no key.

Every action the gate allows (and every one it denies) produces an **Ed25519-signed receipt**. Not a log line — a cryptographic receipt that binds the exact request, the authorising capability, and the policy that permitted it. Those receipts chain together, and the chain bundles into a self-contained **audit pack** that anyone can verify **offline, from a public key, with no network and no cooperation from the cloud provider.**

That last clause is the whole point. The examiner does not have to trust AWS. They do not have to trust *you*. They run one command against a public key and the maths either checks out or it doesn't.

## The two-minute demo

raucle ships a runnable demo of exactly this flow — no AWS account needed, because the transport is stubbed:

```bash
$ python examples/aws_custody/demo.py

[1] agent → GetItem(customers, C-123)  [authorised]
    gate decision : ALLOW
    AWS response  : HTTP 200 (forwarded by raucle)
    receipt       : sha256:908f124582a865...
    agent sees credentials/signature? no

[2] agent → GetItem(audit_logs, *)     [not in the capability]
    gate decision : DENY (TableName contains 'audit_logs' not in allowed_values)
    reached AWS?  : no

[3] building the regulator evidence pack…
    pack written  : demo-output/aws-custody/pack  (4 members)

[4] regulator verifies the pack OFFLINE (no network, no AWS)…
    ✓ index signature
    ✓ member integrity
    ✓ manifest signature
    ✓ receipt chain (3 receipts)
    ✓ reproducible
    ✓ signer is the pinned custodian

    RESULT: VERIFIED
```

Step 4 is the meeting with the examiner, in software. It is the same `verify` an outside party runs:

```bash
$ raucle audit-pack verify ./pack --signer <your-custodian-key-id>
  index signature             PASS
  integrity (member hashes)   PASS
  manifest signature          PASS
  signer matches pinned key   PASS
  receipt chain (offline)     PASS (3 receipts)
  manifest reproducible       PASS
  RESULT: VERIFIED
```

Six independent checks, none of which require AWS to be online or honest: the evidence index is itself signed, every member's hash matches, the receipt chain verifies against the pinned custodian key, and the human-readable report provably matches the signed machine record. Tamper with any byte — the chain, the report, even an unused field — and it reads `REJECTED`. We know, because the test suite forges each of those and asserts the rejection.

## It composes across agents, too

The hard version of the examiner's question is multi-agent: *agent A asked agent B to move the money — prove A was allowed to.* Google's A2A protocol lets agents call each other's skills, but defines no per-skill authorisation a third party can verify. raucle's **A2A binding** fills that slot with the same primitive: agent A attaches a signed hand-off receipt to the call, and agent B — or your examiner, offline — verifies that A was authorised to invoke *that skill* on *that agent*, against a published key. The cross-agent flow becomes one verifiable chain instead of two sets of logs nobody can reconcile.

## Why this is the right standard, not a nice-to-have

There is a reason banks don't run on "trust the application log," and it is the same reason AI agents shouldn't: the entire value of an audit is that it does not depend on the good behaviour — or continued existence — of any single party. Cryptographic, portable, offline-verifiable evidence is what *survives* a provider change, a vendor outage, a hostile insider, or an adversarial examiner. It is the standard regulated industries already demand for everything else. Agentic AI is the first technology in a decade that arrived in production *before* anyone built that standard for it.

raucle is open source. The custody gate, the audit pack, the A2A binding, and the demos above are all in the box:

- `examples/aws_custody/demo.py` — the credential-custody flow end to end
- `raucle audit-pack build | verify` — bundle and offline-verify the evidence
- `examples/a2a_handoff/demo.py` — verifiable per-skill authorisation across agents

If you are the person who will eventually sit across from that examiner, clone it and run the demo. The answer to *"prove what your agent did"* should be a command, not a conversation.

---

*raucle is [open source on GitHub](https://github.com/epic28-ltd/raucle). Building AI agent security to the standard regulated industries already demand — formal, mechanised, provable.*
