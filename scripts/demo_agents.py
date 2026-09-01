#!/usr/bin/env python3
"""Raucle Gateway demo traffic simulator.

Feeds the gateway a continuous, realistic mix of agent tool calls so the
admin panel, topology view, connection log, and receipts stay live for
demonstrations (Sovereign AI demonstrator stage, evaluator accounts).

Traffic profile (per cycle):
  - ~70% benign calls that policies ALLOW
  - ~15% over-threshold or malformed calls the gate DENIES
  - ~15% injection-style calls (unknown tools, wrong source) the gate
    DENIES structurally

Usage:
    python demo_agents.py --gateway http://localhost:8080 [--interval 6]

Runs forever until interrupted; designed for a systemd service or
docker-compose sidecar. No credentials needed: /gate is the agent-facing
endpoint (rate-limited, not secret-bearing).
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Simulated agents. Task = (tool, args, destination). Benign tasks match a
# policy rule exactly (source pattern + tool + constraints); denial tasks
# break exactly one thing so the demo shows specific gate reasons.
# ---------------------------------------------------------------------------

AGENTS = [
    {
        "agent_id": "agent:customer-service",
        "source": "agent:customer-service",
        "name": "Customer Service Bot",
        "benign": [
            ("lookup_balance", {"account": "ACC-003"}, "banking-core"),
            ("lookup_balance", {"account": "ACC-001"}, "banking-core"),
            ("lookup_transaction_history", {"account": "ACC-001", "days": 30}, "banking-core"),
        ],
        "deny": [
            ("lookup_balance", {"account": "ACC-777"}, "banking-core"),
            ("lookup_transaction_history", {"account": "ACC-001", "days": 365}, "banking-core"),
        ],
    },
    {
        "agent_id": "agent:payments-bot",
        "source": "agent:payments-bot",
        "name": "Payments Bot",
        "benign": [
            (
                "transfer_internal",
                {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 2500},
                "internal-ledger",
            ),
            (
                "transfer_external",
                {
                    "from_account": "ACC-001",
                    "to_account": "ACC-003",
                    "amount": 1200,
                    "reference": "INV-2026-001",
                },
                "swift-network",
            ),
            (
                "transfer_internal",
                {"from_account": "ACC-002", "to_account": "ACC-004", "amount": 800},
                "internal-ledger",
            ),
        ],
        "deny": [
            (
                "transfer_internal",
                {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 50000},
                "internal-ledger",
            ),
            (
                "transfer_external",
                {
                    "from_account": "ACC-001",
                    "to_account": "BLACKLIST-001",
                    "amount": 100,
                    "reference": "x",
                },
                "swift-network",
            ),
        ],
    },
    {
        "agent_id": "agent:card-management",
        "source": "agent:card-mgmt-bot",
        "name": "Card Management Agent",
        "benign": [
            (
                "block_card",
                {"card_id": "CARD-001", "reason": "customer reported fraud"},
                "card-processor",
            ),
            ("increase_card_limit", {"card_id": "CARD-002", "new_limit": 5000}, "card-processor"),
        ],
        "deny": [
            ("increase_card_limit", {"card_id": "CARD-002", "new_limit": 500000}, "card-processor"),
            ("unblock_card", {"card_id": "CARD-003"}, "card-processor"),
        ],
    },
    {
        "agent_id": "agent:loan-officer",
        "source": "agent:loan-processing",
        "name": "Loan Officer Assistant",
        "benign": [
            ("check_loan_status", {"application_id": "LOAN-001"}, "loan-origination"),
            (
                "create_loan_application",
                {
                    "applicant_id": "APP-001",
                    "loan_type": "personal",
                    "amount": 15000,
                    "term_months": 36,
                },
                "loan-origination",
            ),
        ],
        "deny": [
            ("check_loan_status", {"application_id": "LOAN-999"}, "loan-origination"),
            (
                "create_loan_application",
                {
                    "applicant_id": "APP-001",
                    "loan_type": "personal",
                    "amount": 900000,
                    "term_months": 36,
                },
                "loan-origination",
            ),
        ],
    },
    {
        "agent_id": "agent:compliance-officer",
        "source": "agent:compliance-aml",
        "name": "Compliance Officer Agent",
        "benign": [
            (
                "file_sar",
                {"transaction_id": "TX-9001", "reason": "unusual pattern", "jurisdiction": "UK"},
                "regulatory-filing",
            ),
            ("check_sanctions", {"entity_name": "SAN-2201-77"}, "sanctions-screening"),
        ],
        "deny": [
            ("check_sanctions", {"entity_name": "JOHN-DOE-CORP"}, "sanctions-screening"),
        ],
    },
]

# Occasionally an "attacker" injects a prompt coercing the agent into a call
# outside its scope. Shows the gate holding the line structurally.
INJECTION_ATTEMPTS = [
    # unknown tool entirely
    (
        "wire_transfer",
        {"recipient": "attacker@example.com", "amount": 50000, "routing": "026009593"},
        "payments-api",
    ),
    # exec primitive that no agent should ever hold
    ("execute_shell", {"command": "cat /etc/passwd"}, "infra-host"),
    # SSRF against cloud metadata
    ("download_file", {"url": "http://169.254.169.254/latest/meta-data/"}, "metadata-endpoint"),
    # right tool, wrong agent (payments-bot token held by customer-service source)
    (
        "transfer_internal",
        {"from_account": "ACC-001", "to_account": "ATTACKER-ACC", "amount": 99999},
        "internal-ledger",
    ),
]


def gate_call(
    gateway: str, tool: str, args: dict, agent_id: str, source: str, destination: str
) -> dict:
    payload = json.dumps(
        {
            "tool": tool,
            "args": args,
            "agent_id": agent_id,
            "source": source,
            "destination": destination,
        }
    ).encode()
    req = urllib.request.Request(
        gateway.rstrip("/") + "/gate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"decision": "ERROR", "status": e.code}
    except Exception as e:
        return {"decision": "ERROR", "error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Raucle demo traffic simulator")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway /gate URL")
    parser.add_argument("--interval", type=float, default=6.0, help="Seconds between calls")
    parser.add_argument("--max-cycles", type=int, default=0, help="0 = run forever")
    parser.add_argument("--quiet", action="store_true", help="Only log errors")
    args = parser.parse_args()

    running = True

    def stop(signum, frame):
        nonlocal running
        running = False
        print("\nshutting down", flush=True)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    cycle = 0
    stats = {"allow": 0, "deny": 0, "escalate": 0, "error": 0}
    print(f"demo agents -> {args.gateway} every {args.interval}s", flush=True)

    while running and (args.max_cycles == 0 or cycle < args.max_cycles):
        cycle += 1
        agent = random.choice(AGENTS)

        # 14% injection attempts; of the rest, benign tasks are weighted 3:1
        # against denial tasks so the demo shows a realistic healthy pipeline
        # (mostly allows with a visible minority of denials).
        if random.random() < 0.14:
            tool, task_args, destination = random.choice(INJECTION_ATTEMPTS)
        else:
            pool = agent["benign"] * 3 + agent.get("deny", [])
            tool, task_args, destination = random.choice(pool)

        result = gate_call(
            args.gateway, tool, task_args, agent["agent_id"], agent["source"], destination
        )
        decision = str(result.get("decision", "ERROR")).upper()
        key = decision.lower()
        if key not in stats:
            key = "error"
        stats[key] += 1

        if not args.quiet:
            reason = str(result.get("reason", ""))[:50]
            print(
                f"  {agent['name'][:24]:24} {tool[:28]:28} -> {decision:8} {reason}"
                f"  (cycle {cycle}, totals {stats})",
                flush=True,
            )

        time.sleep(
            max(0.1, args.interval + random.uniform(-args.interval * 0.3, args.interval * 0.3))
        )

    print(f"final: {stats} over {cycle} cycles", flush=True)


if __name__ == "__main__":
    main()
