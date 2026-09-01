# Conformance Re-verification Layer (Design)

Status: draft design for the proof side of offline verification.

## Problem

A provenance receipt commits only a hash of the call arguments
(`args_hash = sha256(canonical(args))`). A third-party verifier holding the
receipt, the published policy, and the published SMT proof artefact can confirm:

- the receipt's signature is valid,
- the cited schema and policy-proof hashes match the published material,
- the attenuation chain is intact.

The verifier cannot confirm that **this specific call's arguments satisfied the
policy**, because the arguments themselves are hidden behind the hash. Today the
only route is the operator disclosing raw arguments (or an ad-hoc opening) for
per-argument re-checking. That is the gap this layer closes.

The property we want, stated as a verification claim:

> There exist arguments A with sha256(canonical(A)) equal to the args_hash
> committed in receipt R, such that the gate's constraint check over the
> policy P (hash-pinned by R's citation chain) returns ALLOW for A.

## Threat model

- The **operator** wants credit for conformance without exposing sensitive
  arguments (patient records, payment instructions, prompts containing PII).
- The **verifier** (regulator, auditor, partner) wants independent confirmation,
  fail-closed, without trusting the operator's runtime.
- The **adversary** is an operator who emits a conforming-looking receipt for a
  non-conforming call, or an auditor who learns more than the operator disclosed.
- Out of scope (v1): traffic-analysis of which fields get disclosed, and
  side channels in disclosure ordering. The API is pull-based (verifier
  requests fields), so ordering leaks nothing about undisclosed content.

## Layer 1: field-level commitments with selective disclosure

### Commitment

The args object is committed as a Merkle tree over its top-level fields:

- Leaf for field `f` with value `v`:
  `leaf(f, v) = sha256("raucle/d1\x00l\x00" || utf8(f) || "\x00" || canonical_json(v))`
  where `canonical_json` is the receipt spec's RFC 8785 encoding (sorted keys,
  no whitespace, UTF-8, integers only).
- Leaves are ordered by **UTF-16 code unit order** of the field name
  (`sorted(key=lambda f: f.encode("utf-16-be"))`), matching the canonicalisation
  discipline already proven cross-language for receipt bodies. Note UTF-16
  ordering differs from code-point ordering for supplementary characters
  versus the U+E000..U+FFFF range; the vectors pin this.
- Internal node: `node(l, r) = sha256("raucle/d1\x00n\x00" || l || "\x00" || r)`
  over the raw 32-byte child digests.
- Odd node at any level pairs with itself (duplicated right sibling).
- Empty args: root = `sha256("raucle/d1\x00empty")`.

`commit_args(args)` returns the root as `"sha256:<hex>"`, the same shape as
other receipt digests. A future receipt extension field (`x_args_commitment`,
following the established `x_` convention for extension fields) lets a receipt
carry the richer commitment alongside `args_hash`; `args_hash` remains
authoritative for receipts without the extension.

### Disclosure

`disclose_args(args, fields)` produces, for each requested field present in
args, the value plus the Merkle path (sibling digests and sides).
`verify_disclosure(root, disclosures)` recomputes leaves from the disclosed
values, folds the paths, and fails closed on any root mismatch. The output is
the verified field-value mapping: an auditor now holds a set of
cryptographically pinned argument fields and nothing else.

### Partial constraint re-check

With a verified subset of fields, the verifier re-checks what it can:

`recheck_constraints(constraints, disclosed_fields)` evaluates the gate's
normalised constraint kinds (allowed_values, forbidden_values, max_value,
min_value, required_present, starts_with, forbidden_field_combinations) against
the disclosed fields and returns one of:

- SATISFIED: the constraint is verified against disclosed values.
- VIOLATED: the disclosed values demonstrably violate the constraint.
- UNKNOWN: the constraint touches fields that were not disclosed.

UNKNOWN is fail-closed: a re-check report only claims conformance for the
constraints it could actually evaluate. The verifier composes per-constraint
results; a full Layer 2 proof is the only way to convert every UNKNOWN to
SATISFIED without disclosure.

The re-check logic is implemented independently of the gate on purpose: the
verifier re-derives decisions from the spec rather than executing the
operator's runtime. Cross-implementation drift is guarded by test vectors
(the same discipline as the receipt canonicalisation suite).

## Layer 2: zkVM proof of the gate check (next)

Port the constraint checker to a zkVM guest (RISC Zero or SP1, Rust). The
guest program:

1. takes the canonical args bytes (private) and computes their SHA-256,
   constraining the digest to equal the receipt's `args_hash`,
2. takes the policy document and schema (public, hash-pinned to the receipt's
   citations),
3. evaluates the same constraint semantics as the gate,
4. outputs a validity proof binding (args_hash, policy_hash, schema_hash,
   decision).

The verifier API stays identical: `verify_conformance(receipt, published,
proof)` succeeds or fails. Layer 1 disclosures remain useful for spot audits
where a human wants to see actual values.

SHA-256 was chosen throughout (leaves, args_hash, receipt hashes) precisely
because it is the well-trodden path in zk proof systems; no exotic primitives
would be needed to move the scheme on-chain or in-SNARK later.

## Layer 3: full ZK (research)

Express the constraint language as an arithmetic circuit over committed
witnesses and generate succinct proofs (SNARK/STARK). The Lean development
already mechanises the soundness theorem for the modelled constraint kinds;
the Layer 3 circuit would target the same semantics, giving the paper a
proven-guarantee + hidden-witness combination that, to our knowledge, no
receipt scheme currently offers.

## Vector format (follow-up)

A `disclosure-vectors.json` companion file will carry fixed-seed commitment
roots, disclosure paths, and expected re-check outcomes, including the
UTF-16-ordering sharp edge and tamper-rejection cases, so every reference
implementation can be held to the same byte-level standard as the receipt
suite.

## What this is not

This layer does not change the receipt wire format unilaterally. The
`x_args_commitment` extension and any spec amendment go through the normal
proposal path. The module ships as an independent verifier-side capability:
usable by auditors today against gate records, and forward-compatible with
receipts that adopt the extension.