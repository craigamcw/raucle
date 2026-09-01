# raucle as a sidecar to Azure AI Foundry's MCP Gateway

**Status:** Draft proposal, 2026-05-27.
**Authors:** Raucle.
**Target:** shipped — the sidecar lives in `deploy/foundry-mcp-sidecar/` (originally targeted alongside the AGT PDP contract).
**Companion proposals:** [`agent-framework-middleware.md`](./agent-framework-middleware.md), [`agt-pdp-contract.md`](./agt-pdp-contract.md).

## Summary

Azure AI Foundry's "MCP AI Gateway" entered public preview in May 2026,
routing MCP tool calls from Foundry-deployed agents through an Azure
API Management (APIM) instance. Microsoft's own documentation states
the limitation directly:

> *"AI gateways don't log tool traces."*
> — [Govern MCP Tools by Using an AI Gateway, Microsoft Learn, 2026](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/governance)

For regulated industries deploying agents on Foundry, this is the
exact audit primitive their EU AI Act Art. 12 obligation requires.
This proposal specifies a deployment pattern in which raucle runs as
an APIM backend pool member (or transparent sidecar in front of
customer MCP servers), emitting capability receipts for every tool
call routed through the gateway. The receipt is the trace Foundry's
gateway refuses to produce.

This is the lowest-engineering-lift of the three Microsoft integration
moves; the technical bar is deployment configuration, not new code.
The strategic value is sales-led: a concrete deployable answer to a
gap Microsoft has publicly named, in a vertical (regulated AI on
Azure) where raucle's audit-first positioning lands hardest.

## Why now

Three reasons:

1. **Microsoft has publicly conceded the gap.** Foundry's docs name
   tool-tracing as out of scope for the AI gateway. Any prospect
   evaluating Foundry for a regulated workflow encounters this and
   starts asking how to close it. The right answer for those
   conversations is "deploy raucle behind APIM", with a sample config
   on the raucle docs site.
2. **It does not require Microsoft cooperation.** Unlike the AGT PDP
   contract (which needs upstream acceptance to take its strongest
   form), this pattern uses only public APIM features and the customer's
   own MCP servers. Raucle ships the deployment recipe; the customer
   wires it up; Microsoft is informed-but-uninvolved.
3. **Sales motion is short.** Banks, fintechs, and healthcare orgs
   already on Foundry are the highest-velocity raucle prospects. A
   one-page deployment recipe + a working sample is enough for a
   procurement conversation. The conversation gating is not technical;
   it is the existence of the recipe.

## What changes

Three artefacts ship in raucle (see `deploy/foundry-mcp-sidecar/`):

1. `deploy/foundry-mcp-sidecar/apim-policy.xml` — the inbound APIM
   policy that routes Foundry → raucle → customer MCP server.
2. `deploy/foundry-mcp-sidecar/bicep/main.bicep` — Bicep template
   provisioning the raucle sidecar as an Azure Container App in the
   APIM-attached VNet.
3. `deploy/foundry-mcp-sidecar/README.md` — the customer-facing
   walkthrough (15-minute deploy from a clean Foundry project).

No changes to the raucle library itself. The sidecar runs the existing
`raucle serve` HTTP server (already shipped as the `[server]`
extra) behind an APIM frontend.

## The deployment shape

```
   Foundry agent
        │
        │  (MCP tool call: JSON-RPC)
        ▼
   ┌────────────────────────┐
   │ Azure API Management   │
   │  (Foundry-managed)     │
   └─────────┬──────────────┘
             │ inbound policy:
             │   route to raucle backend pool
             ▼
   ┌────────────────────────┐
   │ raucle sidecar         │
   │  (Container App in     │
   │   APIM VNet)           │
   └─────────┬──────────────┘
             │ ALLOW → forward to MCP server
             │ DENY  → return refusal payload to APIM
             ▼
   ┌────────────────────────┐
   │ Customer's MCP server  │
   │  (existing deployment) │
   └────────────────────────┘
             │
             │ (response back up the chain)
             ▼
        (Foundry agent receives result;
         raucle emits capability receipt
         to HashChainSink in parallel)
```

Every tool call passes through raucle. Each call produces a signed
receipt in the customer's audit chain. Foundry's gateway sees raucle
as a normal HTTPS backend; the raucle sidecar sees Foundry's request
as a normal MCP JSON-RPC call. No Foundry-side configuration beyond
the APIM backend-pool member entry.

## The APIM policy

```xml
<!-- deploy/foundry-mcp-sidecar/apim-policy.xml -->
<policies>
  <inbound>
    <base />
    <!-- Forward every MCP call to the raucle sidecar -->
    <set-backend-service base-url="https://raucle-sidecar.${env}.internal/mcp" />
    <!-- Propagate Foundry's Entra agent identity to raucle so the
         receipt can name the agent_id -->
    <set-header name="X-Raucle-Agent-Id" exists-action="override">
      <value>@(context.User.Id ?? "agent:unknown")</value>
    </set-header>
    <!-- Propagate the in-force capability token id (issued by the
         customer's session bootstrap, persisted in the agent's session
         state and forwarded as a header by Foundry's agent runtime) -->
    <set-header name="X-Raucle-Token-Id" exists-action="skip">
      <value>@(context.Request.Headers.GetValueOrDefault("X-Raucle-Token-Id", ""))</value>
    </set-header>
  </inbound>
  <backend>
    <forward-request timeout="30" />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
```

The sidecar's HTTP server reads the two headers, resolves the token,
runs the gate, and either forwards the call to the real MCP server
(stored as `RAUCLE_BACKEND_URL` env var) or returns a JSON-RPC error
response naming the failed constraint.

## The Bicep skeleton

```bicep
// deploy/foundry-mcp-sidecar/bicep/main.bicep
@description('Resource group location')
param location string = resourceGroup().location

@description('Foundry APIM instance ID (existing)')
param apimId string

@description('URL of the customer\'s existing MCP server')
param mcpBackendUrl string

resource sidecar 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'raucle-sidecar'
  location: location
  properties: {
    configuration: {
      ingress: {
        external: false  // VNet-internal only
        targetPort: 8080
      }
    }
    template: {
      containers: [
        {
          name: 'raucle'
          image: 'ghcr.io/epic28-ltd/raucle:latest'  # pin to a release tag in production
          env: [
            { name: 'RAUCLE_BACKEND_URL',        value: mcpBackendUrl }
            { name: 'RAUCLE_ISSUER_KEY_VAULT',   value: '...'        }
            { name: 'RAUCLE_AUDIT_BLOB_CONTAINER', value: '...'      }
          ]
        }
      ]
    }
  }
}

// APIM backend-pool member that points at the sidecar
resource backend 'Microsoft.ApiManagement/service/backends@2025-05-01' = {
  name: '${apimId}/raucle-sidecar'
  properties: {
    url: 'https://${sidecar.properties.configuration.ingress.fqdn}'
    protocol: 'http'
  }
}
```

## What customers wire up themselves

- Provision an Azure Key Vault entry for the raucle issuer's Ed25519
  private key. Mount it into the Container App via Key Vault references.
- Provision an Azure Blob Storage container for the audit log. Mount
  with managed identity.
- Publish the issuer's public key + policy registry on a customer-
  controlled URL (e.g. `https://acme.bank/.well-known/raucle-issuer.pub`)
  so external verifiers — regulators, partners — can fetch them.
- Apply the APIM policy XML to the Foundry-attached APIM operation
  that routes to the MCP server.

The README walks through each step with az-cli commands.

## Backwards compatibility

- Foundry deployments not using the sidecar are unaffected — Foundry's
  default routing (APIM → MCP server, no sidecar) is unchanged.
- The sidecar is a normal APIM backend pool member. Removing it
  removes the receipt-emission step; the agent's tool calls continue
  to work via Foundry's default routing.
- Customers running both raucle-sidecar AND AGT on the same Foundry
  deployment compose cleanly: the sidecar emits receipts for every
  call routed through it; AGT's runtime governance runs alongside.

## Threat-model deltas

The sidecar pattern shifts the trusted-dispatch path. Compared to the
base raucle deployment (raucle inside the agent process):

| Concern | Base raucle | Foundry sidecar |
|---|---|---|
| Bypass risk | Deployer ensures gate is the only path | Customer must configure APIM to route ALL MCP calls through the sidecar; misconfigured routes bypass raucle |
| TLS termination | Agent process | APIM (Foundry-managed) and again at the sidecar VNet edge |
| Issuer key residency | In-process or HSM | Azure Key Vault (Microsoft's HSM-backed managed service) |
| Audit log durability | Local file or HashChainSink | Azure Blob Storage with managed identity |
| Cross-cloud verifiability | Receipt verifies anywhere | Same — APIM is transparent to the receipt format |

The bypass-risk row is the load-bearing one for the deployer. The
README documents the APIM operation-scoping check (every MCP method
on the gateway routes through the sidecar backend; no direct routes
to the MCP server allowed) as a hard prerequisite.

## Non-goals

- Not a replacement for Foundry's existing APIM-based authentication.
  Entra-based agent identity continues to flow through APIM as normal;
  raucle reads the resolved identity from the header APIM injects.
- Not a content-classifier guard. Raucle is the audit-and-authorisation
  primitive; if the customer also wants content scanning, they compose
  with Microsoft Prompt Shields at the same APIM layer.
- Not a fix for the underlying Foundry-AI-gateway limitation. We close
  the audit gap for raucle-using deployments; Microsoft remains the
  party that could close it natively in Foundry, and we should expect
  them to do so eventually. When they do, the sidecar pattern remains
  valid as the cross-cloud-portable alternative.

## Reference-implementation milestones

| M | Deliverable | Target |
|---|---|---|
| M1 | This proposal (design doc) | 2026-05-27 |
| M2 | `deploy/foundry-mcp-sidecar/apim-policy.xml` + the customer-facing README walkthrough | 2 weeks |
| M3 | `deploy/foundry-mcp-sidecar/bicep/main.bicep` (idempotent, az-deployment-tested) | 4 weeks |
| M4 | End-to-end sample: a Foundry agent project + the deployed sidecar + a sample MCP server, with the receipt log verifiable offline. Recorded as a walkthrough video. | 6 weeks |
| M5 | Documented compatibility configuration for running alongside AGT (Microsoft's other layer); see AGT PDP proposal. | 8 weeks |

## Open questions

1. **Token propagation through Foundry's agent runtime.** Foundry
   today does not document a per-session-header propagation mechanism
   for arbitrary headers; the `X-Raucle-Token-Id` header in the APIM
   policy assumes Foundry's runtime will forward it. M2 confirms this
   against a real Foundry deployment; if it doesn't, the fallback is
   to derive the token from Foundry's session id via a raucle-side
   token-store lookup.
2. **APIM cold-start latency.** APIM adds 5–10 ms of routing latency
   on a warm path; the sidecar adds another 5 ms for the gate check
   plus receipt emission. End-to-end (Foundry → APIM → sidecar →
   MCP server) is roughly 25–40 ms over a cold gateway. M2 measures
   on a real Foundry deployment and documents the number.
3. **Audit log durability under sidecar pod restart.** The HashChainSink
   guarantees in-process append correctness; M3 confirms the Blob
   Storage flush cadence is acceptable (i.e., that an unexpected pod
   restart loses no more than the configured `checkpoint_every` events).

## Why this is the right move for raucle

Three reasons:

1. **It is the lowest-engineering-lift, highest-sales-lift integration
   in the Microsoft-stack work.** The sidecar runs the existing
   `raucle serve` binary unchanged; the deliverable is a
   deployment recipe and a Bicep template, not new library code.
2. **The pitch line is unusually clean.** *"EU AI Act Article 12
   evidence that Foundry doesn't give you, signed and verifiable
   offline."* Most enterprise-sales conversations are not this neat.
3. **It complements rather than competes with the AGT PDP work.**
   Customers who deploy on Foundry without AGT get the sidecar pattern.
   Customers who deploy on AGT (with or without Foundry) get the PDP
   integration. Customers on neither get the Agent Framework
   middleware. The three proposals together cover the full
   Microsoft-shop deployment matrix without overlap.
