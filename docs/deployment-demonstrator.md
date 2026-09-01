# Sovereign AI Demonstrator Deployment

This deployment runs the raucle gateway with live simulated agent traffic for
evaluator viewing: the [Sovereign AI R&D Procurement
Scheme](https://www.gov.uk/government/organisations/sovereign-ai) requires
demonstrator-stage technologies "ready to be tested in real-world operational
environments". This compose file provides that environment.

## What runs

| Service | Purpose | Port |
|---|---|---|
| `raucle-gateway` | The gate, receipts, policy engine | internal 8080 |
| `raucle-gateway` (admin) | Admin panel: dashboard, connection log, policy editor, receipts, SIEM, topology | 8091 via caddy |
| `demo-agents` | Simulated agents feeding a realistic allow/deny mix through the gateway continuously | - |
| `caddy` | TLS termination, security headers, rate limiting | 443 |

## The demo traffic

`scripts/demo_agents.py` simulates five banking agents (customer service,
payments, card management, loan officer, compliance) plus occasional
injection-style attacks. The profile is roughly:

- **~69% ALLOW** — policy-conformant calls (allowed accounts, in-bounds
  amounts, required fields present)
- **~31% DENY** — specific, visible gate reasons: allowlist violations,
  over-limit amounts, missing required fields, blacklisted destinations,
  unknown tools, agent/source mismatches

Every decision produces a receipt and a connection-log entry, so the admin
panel dashboard, live connection flow, topology view, and receipt viewer all
show continuously-updating activity.

## Read-only evaluator account

Evaluators get the `auditor` role: **stats, connections, and receipts only**.
Policies, users, configuration, and SIEM settings are 403. The account cannot
modify anything and cannot enumerate other accounts.

Create it (as admin):

```bash
curl -X POST http://localhost:8081/api/users \
  -H "Authorization: Bearer $RAUCLE_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "<evaluator-key>", "role": "auditor", "name": "Sovereign AI Evaluator"}'
```

The evaluator then logs into the admin panel with their own API key and sees
the live dashboard, connection log, and receipt browser. TOTP MFA can be
enabled on the account the same way as any user
(POST `/api/users/<key>/mfa/setup`).

## Deploy

```bash
RAUCLE_ADMIN_KEY=<admin-key> RAUCLE_DOMAIN=<domain> docker compose -f docker-compose.gateway.yml up -d --build
```

The gateway loads all six example policy sets (banking, fintech, healthcare,
insurance, ecommerce, data-ops — 80 rules) from `policies/examples/`, mounted
read-only at `/etc/raucle/policies-demo`.

## What an evaluator should look at

1. **Dashboard** (`/`) — live allow/deny/escalate counters, latency, top tools
2. **Live topology** (Connections tab) — source nodes left, gate/tools centre, destinations right, animated traffic particles; click a node to isolate its paths; the deny filter marks blocked nodes with glowing red loops
3. **Connection log** — each row is a gated call: source agent → policy applied
   → decision with reason; filterable by tool, decision, source
4. **Receipts** — the cryptographic evidence for any decision, offline-verifiable
5. **Policy editor** (admin only) — the YAML DSL as a risk officer writes it
6. **Learn mode** (admin only) — with `RAUCLE_LEARN_MODE=true`, the gate records every call it denied for having no matching policy and drafts candidate rules from the observed traffic. Fail-closed by design: learning never authorises; the operator reviews the draft, copies it into the policy editor, and deploys.

## Learn mode (onboarding a new agent)

To onboard an agent you do not yet have a policy for:

1. Set `RAUCLE_LEARN_MODE=true` and restart the gateway
2. Point the new agent at `/gate` — every call fails closed with "no policy configured", and the gate records what the agent tried to do
3. Open the **Learn** tab: observed tools, call counts, and agents
4. Click **Copy into Policy Editor** — the drafted rules appear as YAML: allow lists for low-cardinality string fields, min/max bounds (10% headroom) for numerics, required fields seen in every call
5. Review, tighten, **Save & Deploy**, then **Reload** — the agent now runs under a reviewed policy