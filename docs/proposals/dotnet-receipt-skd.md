# Raucle Receipt SDK for .NET (I5 + I1)

**Status:** Draft proposal, 2026-05-28.
**Authors:** Raucle.
**Target:** New repo `raucle-receipt-dotnet` (NuGet `Raucle.Receipt`),
plus `Raucle.AgentFramework` for the Microsoft Agent Framework .NET
runtime.

## Summary

Microsoft's Agent Framework ships first-class .NET support alongside
Python. Enterprise customers building agents on Azure / Windows /
.NET 8+ need a Raucle SDK in their runtime. This proposal scopes two
NuGet packages:

1. **`Raucle.Receipt`** — pure C# implementation of the Provenance
   Receipt v1 spec (mirrors `@raucle/receipt`). Ed25519 signing,
   canonical-JSON serialisation, JWS compact-form output, verifier
   that mirrors the Python `ProvenanceVerifier` semantics. Zero
   runtime deps beyond `Microsoft.IdentityModel.Tokens` for Ed25519
   (or BouncyCastle if we want zero-trust on M$ crypto).

2. **`Raucle.AgentFramework`** — middleware for the .NET Agent
   Framework runtime (`Microsoft.AgentFramework` ≥ 1.0). Equivalent
   surface to `raucle.integrations.agent_framework` in Python:
   a `RaucleFunctionMiddleware` that hooks `FunctionInvocationContext`,
   checks an in-force capability token, emits a signed receipt, and
   short-circuits on deny.

## Why these two and not just one

`Raucle.AgentFramework` consumes `Raucle.Receipt` types but has its
own dependency on the Agent Framework SDK. Splitting them lets
non-Agent-Framework .NET deployments (ASP.NET Core APIs, Worker
services, Windows services) install only the receipt primitives and
avoid the heavier runtime dep.

## Out of scope for v0.1

- LangChain.NET / Semantic-Kernel adapters (separate packages, after
  the core .NET surface is proven).
- F# convenience wrappers.
- ARM-template / Bicep modules — those belong in a separate
  `Raucle.Azure.Deploy` package.

## Receipt-spec parity

`Raucle.Receipt` must produce JWSes that the Python
`ProvenanceVerifier` and the TypeScript `ProvenanceVerifier` accept
without modification. Tests cross-verify a vector matrix:

| Generator | Verifier | Tests |
|---|---|---|
| Python | C# | `tests/cross-lang/python-to-dotnet.spec.cs` |
| C# | Python | `tests/cross-lang/dotnet-to-python.spec.py` |
| C# | TypeScript | `tests/cross-lang/dotnet-to-typescript.spec.ts` |
| TypeScript | C# | `tests/cross-lang/typescript-to-dotnet.spec.cs` |

A fixed-seed deterministic test vector lives in
`docs/spec/provenance/v1/test-vectors/` and is referenced from each
SDK's test suite.

## Surface sketch

```csharp
using Raucle.Receipt;

var identity = AgentIdentity.Generate(new AgentIdentityOptions {
    AgentId = "agent:billing-agent",
    AllowedModels = new[] { "gpt-4o" },
});

var receipt = new ProvenanceReceipt {
    AgentId    = identity.AgentId,
    AgentKeyId = identity.KeyId,
    Operation  = Operation.ToolCall,
    Tool       = "lookupCustomer",
    InputHash  = Hash.Object(args),
    Parents    = new[] { previous.ReceiptHash },
    IssuedAt   = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
};
receipt.Sign(identity);
await sink.AppendAsync(receipt);
```

```csharp
using Raucle.AgentFramework;

var middleware = new RaucleFunctionMiddleware(
    gate: gate,
    sink: sink,
    leanTheoremId: "vcd.gate_soundness");

var agent = builder
    .UseFunctionMiddleware(middleware)
    .Build();
```

## Milestones

- **M1** — `Raucle.Receipt` v0.1 + cross-lang test vector suite.
- **M2** — `Raucle.AgentFramework` v0.1 + integration tests against
  AF 1.0 .NET runtime.
- **M3** — NuGet publish + docs page on raucle.com/sdk/dotnet.
- **M4** — Streaming-tool-output receipts (matches Python adapter's
  known limitation).

## Risk

The biggest risk is Ed25519 surface: .NET 8's built-in
`System.Security.Cryptography` Ed25519 support is still preview on
some runtimes (notably Windows). Decision: BouncyCastle for v0.1
to remove platform variation; reassess for v0.2 once .NET 10 GA.

## Open questions

- [DECIDE]: Source-generator vs. reflection for canonical JSON.
  Source-generator wins on AOT (Azure Functions, MAUI), reflection
  wins on dev ergonomics. Lean toward source-generator for the
  receipt primitives, reflection acceptable for the AF middleware
  helpers.

- [DECIDE]: Whether `Raucle.AgentFramework` should depend on
  `Microsoft.AgentFramework` directly (single TFM) or
  `Microsoft.AgentFramework.Abstractions` only (looser coupling).
  The Python adapter only depends on the abstract `FunctionMiddleware`
  base — mirror that.

## Track

A skeleton repo will be created at
`github.com/epic28-ltd/raucle-receipt-dotnet` once this proposal is
green-lit. Initial scaffolding:

```
raucle-receipt-dotnet/
├── src/
│   ├── Raucle.Receipt/Raucle.Receipt.csproj
│   └── Raucle.AgentFramework/Raucle.AgentFramework.csproj
├── tests/
│   ├── Raucle.Receipt.Tests/
│   └── Raucle.AgentFramework.Tests/
├── docs/
└── Raucle.Dotnet.sln
```
