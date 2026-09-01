# Reference implementations — Raucle Provenance Receipt v1

Independent, interoperable implementations of the
[Provenance Receipt v1 spec](../docs/spec/provenance/v1.md). All emit and
verify the same wire format and compute **byte-identical content-addressed
receipt IDs** — a receipt produced by any one verifies in the others.

| Language | Directory | Crypto | Notes |
|---|---|---|---|
| **Python** | (in the main library: [`raucle/provenance.py`](../raucle/provenance.py)) | `cryptography` (Ed25519) | The canonical reference; ships with the engine. |
| **TypeScript** | [`provenance-ts/`](./provenance-ts) | Node `webcrypto` (Ed25519) | Zero runtime deps. |
| **Go** | [`provenance-go/`](./provenance-go) | stdlib `crypto/ed25519` | stdlib-only. |
| **Rust** | [`provenance-rs/`](./provenance-rs) | `ed25519-dalek` | `cargo test`. |
| **C# / .NET** | [`provenance-cs/`](./provenance-cs) | BouncyCastle (Ed25519) | net8.0; cross-platform, no Windows needed. |

Each implements: `emit` / `verify` (Compact JWS, `typ=provenance-receipt/v1`,
`crit=["raucle/v1"]`, content-addressed id), payload validation (§4),
and chain/DAG validation with taint monotonicity (§7–§9).

## Cross-language interoperability

The guarantee that makes this a *standard* and not five lookalikes: the
canonical-JSON encoder in every implementation produces the same bytes,
so the signed input and the SHA-256 receipt id are identical across
languages. This is verified end-to-end — e.g. a receipt emitted by the
C# or Rust implementation verifies in the Python implementation and
yields the same id for the same key + payload. Each implementation also
carries a `canonical parity` test pinning its output to the shared
vector:

```
{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}
```

Shared conformance test vectors for the receipt and the related
capability/proof artifacts live in
[`../docs/spec/provenance/v1/test-vectors.json`](../docs/spec/provenance/v1/test-vectors.json)
and [`../standards/test-vectors/`](../standards/test-vectors).

## Installing from package registries

Each implementation is published to its ecosystem's registry (all MIT;
first registry release: `ref-v0.1.0`):

```bash
pip install raucle          # Python — ships inside the main library
npm install @raucle/provenance     # TypeScript / Node >= 20
cargo add raucle-provenance        # Rust
dotnet add package Raucle.Provenance   # C# / .NET 8+
go get github.com/epic28-ltd/raucle/reference/provenance-go  # Go
```

Registry releases are cut by tagging `ref-v<version>` (see
[`.github/workflows/publish-reference.yml`](../.github/workflows/publish-reference.yml));
a release only ships after the cross-language conformance harness passes on
all five ports, and the npm package carries a provenance attestation.

## Building / testing each

```bash
# TypeScript
cd provenance-ts && npm install && npm test
# Go
cd provenance-go && go test ./...
# Rust
cd provenance-rs && cargo test
# C#
cd provenance-cs && dotnet test test/Raucle.Provenance.Tests.csproj
```

All five reference implementations are **MIT-licensed** (see
[`LICENSE`](./LICENSE)) — deliberately permissive so the standard is
trivial to adopt in any product, including proprietary ones. The engine in
the rest of this repository is Apache-2.0 (also permissive, with an explicit
patent grant); see [`../GOVERNANCE.md`](../GOVERNANCE.md).
The specification itself is CC-BY-4.0. Contributions of further language
ports are welcome — keep the canonical-JSON bytes identical to the
vector above and add a parity test.

## Framework integrations
- **[`a2a-provenance/`](./a2a-provenance)** — verifiable per-skill
  authorisation for Google's A2A (Agent-to-Agent) protocol: emit +
  verify `agent_handoff` receipts bound to an Agent Card extension.
  See the [binding profile](../standards/a2a/README.md).

- **[`vercel-ai-middleware/`](./vercel-ai-middleware)** — gate Vercel AI SDK
  (`ai` ≥ 4) tool calls against a capability policy and emit a signed
  receipt per decision, built on the TypeScript implementation above.
  (Python integrations for the Microsoft Agent Framework, LangChain, and
  AutoGen live in [`raucle/integrations/`](../raucle/integrations).)
