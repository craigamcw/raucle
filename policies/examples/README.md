# Policy Examples

Ready-to-use policy files for the Raucle Gateway. Each file demonstrates
the policy DSL for a specific industry. Copy, edit the issuer, agent IDs,
and constraint values to match your deployment.

## Files

| File | Industry | Tools | Key Features |
|------|----------|-------|--------------|
| `banking-payments.yaml` | Banking | Transfers, cards, loans, compliance | Multi-tier approval, sanctions screening, SAR filing |
| `healthcare-medical.yaml` | Healthcare | Prescriptions, imaging, lab tests, records | PHI controls, controlled substances, diagnostic approval |
| `fintech-payments.yaml` | Fintech | Card payments, fraud, KYC/AML, merchant ops | Velocity limits, geo-blocking, merchant onboarding |
| `enterprise-data-ops.yaml` | Enterprise | Databases, cloud, secrets, security scans | Data residency, resource quotas, secret path controls |
| `ecommerce-retail.yaml` | Retail | Orders, inventory, pricing, shipping | Order limits, stock write-offs, pricing guardrails |
| `insurance.yaml` | Insurance | Claims, underwriting, policy admin, risk | Claim thresholds, underwriting limits, fraud referral |

## Usage

```bash
# Copy an example to your gateway config
cp policies/examples/banking-payments.yaml /etc/raucle/policies.yaml

# Edit the issuer and agent IDs to match your deployment
vi /etc/raucle/policies.yaml

# Hot-reload via the admin panel API
curl -X POST http://localhost:8081/api/policies/reload \
  -H "Authorization: your-admin-key"
```

## Constraint Types

| DSL Key | Gate Constraint | Purpose |
|---------|----------------|---------|
| `allow` | `allowed_values` | Whitelist permitted field values |
| `deny` | `forbidden_values` | Denylist blocked field values |
| `max` | `max_value` | Numeric ceiling per field |
| `min` | `min_value` | Numeric floor per field |
| `require` | `required_present` | Mandatory fields |
| `starts_with` | `starts_with` | Prefix matching (e.g. `ACC-` prefix) |
| `forbidden_combinations` | `forbidden_field_combinations` | Mutually exclusive field pairs |
| `require_approval_when` | (escalation) | Human-in-the-loop threshold |

## Source/Destination Matching

Each policy rule can specify `source` and `destination` match patterns.
The gateway only applies the rule if the inbound tool call matches both
patterns. This lets you load multiple policy files and have each file
govern traffic for specific sources or destinations.

```yaml
policies:
  - tool: transfer_money
    source: "agent:payments*"        # only payments agents
    destination: "swift-network*"    # only SWIFT transfers
    agent_id: agent:payments-bot
    constraints:
      allow:
        from_account: ["ACC-001"]
```

Patterns support `*` and `?` wildcards (fnmatch). Empty or `"*"`
means "match anything". The gateway finds the **first matching rule**
for each tool call, checking all loaded policy files in order.

## Multiple Policy Files

Set `RAUCLE_POLICY_DIR` to a directory containing multiple `.yaml` files.
The gateway loads all of them and matches tool calls by source/destination:

```bash
# Load all policy files from /etc/raucle/policies/
RAUCLE_POLICY_DIR=/etc/raucle/policies/

# Or use a single file (default)
RAUCLE_POLICY_FILE=/etc/raucle/policies.yaml
```

Example directory structure:
```
/etc/raucle/policies/
  banking.yaml          # banking and payments policies
  healthcare.yaml       # medical and clinical policies
  enterprise-ops.yaml   # cloud, database, security operations
```

## Approval Thresholds

The `require_approval_when` key triggers human approval before execution.
Use field-comparison operators:

```yaml
require_approval_when:
  amount_gt: 5000        # approve when amount > 5000
  risk_score_gte: 80     # approve when risk_score >= 80
  order_count_lt: 1      # approve when order_count < 1
```

An empty `require_approval_when: {}` means the action ALWAYS requires
human approval, regardless of the arguments.

## Wildcards

Wildcards (`*`) are rejected in `allow` constraints. Use `starts_with`
instead:

```yaml
# Wrong:
allow:
  account: ["ACC-*"]    # rejected

# Right:
starts_with:
  account: ["ACC-"]     # matches any account starting with ACC-
```

## Validating a Policy File

```bash
# Via the admin API
curl -X POST http://localhost:8081/api/policies/validate \
  -H "Authorization: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"content": "$(cat policies.yaml)"}'

# Via Python
from raucle.policy import PolicyFile
policy = PolicyFile.load("policies.yaml")
print(f"Loaded {len(policy.policies)} rules for {policy.issuer}")
```