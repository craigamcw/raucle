# Control Pattern: Capability Tokens for LLM Agent Tool Calls

**Submission target:** OWASP AI Exchange — Threats Through Use, Indirect Prompt Injection mitigations.
**Profile identifier:** `cap:v1`
**Status:** draft for public comment.
**Last updated:** 2026-05-14.

## What this control addresses

OWASP AI Exchange currently lists *indirect prompt injection* as one of the most-cited attack patterns against LLM-integrated applications, with the dominant mitigation pattern being model-side (filtering, paraphrasing, structured queries). This contribution proposes a complementary mitigation that operates at the **tool-invocation boundary**, not the model-input boundary.

The control's claim is: for every tool call an agent attempts to execute, that call must carry an **unforgeable capability token** whose constraints are satisfied by the actual call arguments. Tool runtimes refuse to execute calls without a valid token. The model is free to be talked into anything by injected text; the gate doesn't read text.

## Threat model

Within the broader AI Exchange threat model, this control specifically addresses:

- **TT.IPI** Indirect Prompt Injection via tool output / RAG context / web content.
- **TT.OOC** Out-of-Context Tool Misuse (the agent calls a tool the user didn't authorise).
- **TT.PE**  Tool-Mediated Privilege Escalation (legitimate session token misused for unauthorised action).

The control does **not** address:

- Free-form text exfiltration (model says secret in its response).
- Side-channel encoding within otherwise-legitimate parameter values.
- Compromise of the token issuer's signing key (out of scope, addressed by standard HSM practice).

## The `cap:v1` token format

A capability token is a content-addressed, Ed25519-signed JSON object with the following fields, all required unless marked optional:

```json
{
  "version":           "cap:v1",
  "token_id":          "cap:8f3a91…",
  "agent_id":          "agent:billing.invoice",
  "tool":              "transfer_funds",
  "constraints": {
    "max_value":        {"amount": 100},
    "forbidden_values": {"recipient": ["attacker@evil.example"]},
    "allowed_values":   {"currency": ["USD", "EUR", "GBP"]}
  },
  "issuer":            "platform.example",
  "key_id":            "8fa2ffa741ba6e3a",
  "issued_at":         1747225200,
  "not_before":        1747225200,
  "expires_at":        1747228800,
  "parent_id":         "cap:7d2e84…",
  "policy_proof_hash": "sha256:7c3e94…",
  "signature":         "MEUCIQ…"
}
```

### Field semantics

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | string | yes | Profile identifier. `cap:v1` for this revision. |
| `token_id` | string | yes | Self-descriptor: `cap:` followed by the first 24 hex chars of SHA-256 over the canonical-JSON serialisation of the body fields (every field except `signature` and `token_id` itself). |
| `agent_id` | string | yes | The principal authorised to present this token. Must match `^agent:[a-z0-9][a-z0-9_\-./]{0,127}$`. Sub-scoping via dotted prefix (e.g. `agent:billing` is a parent of `agent:billing.invoice`). |
| `tool` | string | yes | The exact tool name the token authorises. Must match `^[A-Za-z0-9][A-Za-z0-9_\-./]{0,127}$`. |
| `constraints` | object | yes | Value-level restrictions on call arguments. See "Constraint vocabulary" below. |
| `issuer` | string | yes | Free-form identifier for the issuing authority. |
| `key_id` | string | yes | First 16 hex chars of SHA-256 over the issuer's Ed25519 public-key PEM. Verifiers use this to look up the public key in their trusted-issuer map. |
| `issued_at` | integer | yes | Unix epoch seconds. |
| `not_before` | integer | yes | Unix epoch seconds. Tokens are invalid if `now < not_before`. |
| `expires_at` | integer | yes | Unix epoch seconds. Tokens are invalid if `now ≥ expires_at`. |
| `parent_id` | string \| null | optional | If set, `token_id` of the parent in an attenuation chain. |
| `policy_proof_hash` | string \| null | optional | If set, SHA-256 of a `proof:v1` artefact certifying the constraints are complete over the tool's declared JSON Schema. |
| `signature` | string | yes | Base64url-encoded Ed25519 signature over the canonical-JSON serialisation of the body fields. |

### Canonical-JSON serialisation

Used for `token_id` computation and signature input. Rules:

1. Object keys sorted by UTF-16 code unit (the ordering of [RFC 8785 §3.2.3](https://www.rfc-editor.org/rfc/rfc8785#section-3.2.3)): keys are compared as sequences of unsigned 16-bit UTF-16 code units. This coincides with Unicode code-point order for BMP characters and differs only for non-BMP (astral) characters; specifying it precisely (rather than a vague "lexicographic") is required for cross-language byte-identity. String values in allow/deny lists are ordered the same way.
2. No whitespace between tokens. Use `",", ":"` separators.
3. UTF-8 encoding throughout. Unicode escapes (`\uXXXX`) not used unless the character is a JSON control character.
4. Integer values rendered without leading zeros, sign, or trailing decimal.
5. Floating-point values not used in token bodies. Constraints over numeric fields use integer comparators only at the `cap:v1` profile level.

The `token_id` and `signature` fields are **excluded** from the canonical body during hashing/signing.

### Constraint vocabulary

The `constraints` object permits the following keys, all optional. Multiple constraints compose as conjunction (all must hold for the call to be authorised).

| Key | Shape | Semantics |
|---|---|---|
| `forbidden_values` | `{field: [values, …]}` | Call denied if `args[field]` equals any listed value. Field-level scalar or list-element check. |
| `allowed_values` | `{field: [values, …]}` | Call denied if `args[field]` is **not** one of the listed values. |
| `max_value` | `{field: bound}` | Call denied if `args[field] > bound`. Numeric fields only. |
| `min_value` | `{field: bound}` | Call denied if `args[field] < bound`. |
| `required_present` | `[field, …]` | Call denied if any listed field is missing from `args`. |
| `forbidden_present` | `[field, …]` | Call denied if any listed field is present in `args`. |
| `forbidden_field_combinations` | `[[field_a, field_b, …], …]` | Call denied if every field in a sub-list is present together. |

Field references resolve to the top-level keys of the call's `args` object. Nested field paths (`field.subfield`) are reserved for `cap:v2`.

## Attenuation

A holder of a parent token may derive a more-restricted child token. The derivation operation produces a new token where:

- `tool` is identical to the parent's.
- `agent_id` is identical to the parent's, or a sub-scope of it (prefix-extension by `.`).
- For each constraint kind, the child's bound is at least as tight as the parent's: `forbidden_values` is a superset (union), `allowed_values` is a subset (intersection), `max_value` is the minimum, `min_value` is the maximum.
- `expires_at` is no later than the parent's.
- `parent_id` is set to the parent's `token_id`.
- `issued_at` and `not_before` are set to the child's mint time.
- The child is signed by an issuer the verifier trusts.

A conforming implementation MUST reject any derivation that violates these invariants.

## Verification (gate-side)

A tool runtime acting as a gate MUST perform the following checks before executing a call. Any failure MUST result in DENY with a structured reason.

1. **Issuer pinning.** The token's `key_id` appears in the gate's `trusted_issuers` map.
2. **Signature.** The Ed25519 signature verifies under the pinned public key over the canonical body.
3. **Identifier binding.** Recomputing `token_id` from the canonical body matches the value in the token.
4. **Time bounds.** `not_before ≤ now < expires_at`.
5. **Tool match.** Token's `tool` equals the requested tool name.
6. **Agent scope.** The caller's claimed `agent_id` equals or is a sub-scope of the token's `agent_id`.
7. **Constraint satisfaction.** Every constraint in the token holds against the actual `args`.
8. **Chain resolution** (optional). If `parent_id` is non-null and the gate is configured to verify chains, each ancestor MUST verify under the same trusted-issuer map.

A conforming gate MAY perform additional checks beyond these eight; it MUST NOT skip any of them.

## Trust model

This profile does NOT define a global root of trust. Each gate operator maintains its own `trusted_issuers` allowlist (one or more `(key_id, public_key_pem)` pairs). Multiple issuers may be pinned simultaneously (e.g. a platform issuer + a customer's own issuer); a token verifies if its `key_id` is in the set.

There is no central token registry. Tokens are bearer artefacts: anyone holding a valid token may present it to the gate. Confidentiality of tokens is the deployer's responsibility (mTLS, short TTLs, session-bound delivery).

## Cryptographic dependencies

- **Ed25519** signatures (RFC 8032, FIPS 186-5).
- **SHA-256** for `token_id` and `key_id` derivation (FIPS 180-4).
- Canonical-JSON encoding as specified above.

No new cryptographic primitives are introduced.

## Reference implementation

Apache-2.0 Python implementation in [github.com/epic28-ltd/raucle](https://github.com/epic28-ltd/raucle), file `raucle/capability.py`. ~280 lines. Test suite covers signing, expiry, tampering, every attenuation invariant, full chain verification, and serialisation round-trips. Lean 4 mechanisation of the attenuation and gate-soundness theorems lives in `paper/lean/`.

## Interoperability test vectors

The reference implementation ships a test vector set under `tests/cap_vectors/`. A conforming `cap:v1` implementation MUST round-trip every vector:

- Vector 1: minimal token, no constraints, no parent.
- Vector 2: token with one `max_value` constraint, one `allowed_values` constraint.
- Vector 3: attenuated child of vector 2 with tightened `max_value`.
- Vector 4: token with non-null `policy_proof_hash` referencing the `proof:v1` vector.
- Vector 5: deliberately-tampered token (one byte flipped in the canonical body), MUST fail verification.

## Open questions for review

1. **Numeric encoding.** `cap:v1` restricts numeric constraints to integers because float canonicalisation is hard. Should `cap:v2` include a defined float-canonicalisation scheme (e.g. IEEE-754 binary64 fixed-format)?
2. **Constraint extensibility.** Should `cap:v1` define an extension point (`x-` prefixed constraint keys), or require profile-level changes?
3. **Revocation.** Currently expiration is the only revocation mechanism. Should `cap:v1` define a revocation-feed format, or leave revocation to higher-level systems (e.g. CRL-style)?

## What we ask of OWASP AI Exchange

Acceptance as an informational control pattern under "Indirect Prompt Injection mitigations". Specifically:

- A control entry that references this document.
- A note in the threat-model section that this control complements model-side defences and is most-effective when combined with them.
- Acceptance of the `cap:v1` identifier as the profile name.

Subsequent revisions (post-public-comment) may apply for full normative-control status.
