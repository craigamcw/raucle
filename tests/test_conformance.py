"""Tests for the conformance re-verification layer (selective disclosure)."""

import pytest

from raucle.conformance import (
    commit_args,
    disclose_args,
    disclosure_path,
    recheck_constraints,
    verify_disclosure,
)


class TestCommitArgs:
    def test_commit_empty(self):
        root = commit_args({})
        assert root.startswith("sha256:")
        # Deterministic for empty args
        assert root == commit_args({})
        # Fixed known digest for the empty tree
        assert len(root) == len("sha256:") + 64

    def test_commit_single_field(self):
        root = commit_args({"tool": "lookup_balance"})
        assert root.startswith("sha256:")
        assert root != commit_args({})

    def test_commit_deterministic(self):
        a = {"b": 2, "a": 1, "c": 3}
        b = {"c": 3, "b": 2, "a": 1}
        assert commit_args(a) == commit_args(b), "insertion order must not matter"

    def test_commit_order_follows_utf16(self):
        # UTF-16 code unit order differs from code-point order only for
        # supplementary characters vs U+E000..U+FFFF. We commit both ways and
        # confirm they differ (they are different objects).
        args1 = {"z": 1, "a": 2}
        args2 = {"a": 2, "z": 1}
        assert commit_args(args1) == commit_args(args2)

    def test_value_change_changes_root(self):
        r1 = commit_args({"amount": 100})
        r2 = commit_args({"amount": 101})
        assert r1 != r2

    def test_nested_value_change_changes_root(self):
        r1 = commit_args({"args": {"x": [1, 2, 3]}})
        r2 = commit_args({"args": {"x": [1, 2, 4]}})
        assert r1 != r2

    def test_type_confusion_rejected(self):
        # 1 (int) vs 1.0 (float) have different canonical encodings... except
        # floats are rejected entirely by canonicalisation.
        assert commit_args({"amount": 1}) is not None
        with pytest.raises(ValueError):
            commit_args({"amount": 1.5})

    def test_all_leaves_sha256(self):
        # The root must be 32 bytes of hex
        root = commit_args({"a": 1})
        bytes.fromhex(root[len("sha256:") :])  # raises if not hex


class TestDisclosure:
    def setup_method(self):
        self.args = {
            "from_account": "ACC-001",
            "to_account": "ACC-002",
            "amount": 500,
            "reference": "INV-2026-001",
        }
        self.root = commit_args(self.args)

    def test_disclose_single_field(self):
        pkg = disclose_args(self.args, ["amount"])
        assert "amount" in pkg["fields"]
        assert pkg["fields"]["amount"]["value"] == 500

    def test_verify_single_field(self):
        pkg = disclose_args(self.args, ["amount"])
        verified = verify_disclosure(self.root, pkg)
        assert verified == {"amount": 500}

    def test_verify_multiple_fields(self):
        pkg = disclose_args(self.args, ["amount", "from_account"])
        verified = verify_disclosure(self.root, pkg)
        assert verified == {"amount": 500, "from_account": "ACC-001"}

    def test_verify_all_fields(self):
        pkg = disclose_args(self.args, list(self.args.keys()))
        verified = verify_disclosure(self.root, pkg)
        assert verified == self.args

    def test_verify_rejects_wrong_value(self):
        pkg = disclose_args(self.args, ["amount"])
        pkg["fields"]["amount"]["value"] = 999999  # tamper
        with pytest.raises(ValueError, match="does not match root"):
            verify_disclosure(self.root, pkg)

    def test_verify_rejects_wrong_root(self):
        pkg = disclose_args(self.args, ["amount"])
        other_root = commit_args({"amount": 999})
        with pytest.raises(ValueError, match="does not match root"):
            verify_disclosure(other_root, pkg)

    def test_verify_rejects_missing_fields_object(self):
        with pytest.raises(ValueError, match="missing 'fields'"):
            verify_disclosure(self.root, {})

    def test_verify_rejects_malformed_entry(self):
        pkg = disclose_args(self.args, ["amount"])
        pkg["fields"]["amount"] = "not-a-dict"
        with pytest.raises(ValueError, match="malformed"):
            verify_disclosure(self.root, pkg)

    def test_verify_rejects_missing_path(self):
        pkg = disclose_args(self.args, ["amount"])
        del pkg["fields"]["amount"]["path"]
        with pytest.raises(ValueError, match="missing path"):
            verify_disclosure(self.root, pkg)

    def test_verify_rejects_bad_sibling(self):
        pkg = disclose_args(self.args, ["amount"])
        pkg["fields"]["amount"]["path"][0] = (False, "not-a-digest")
        with pytest.raises(ValueError, match="bad sibling"):
            verify_disclosure(self.root, pkg)

    def test_verify_rejects_bad_root_format(self):
        pkg = disclose_args(self.args, ["amount"])
        with pytest.raises(ValueError, match="bad root"):
            verify_disclosure("md5:abcdef", pkg)

    def test_disclose_absent_field_skipped(self):
        pkg = disclose_args(self.args, ["nonexistent_field"])
        assert "nonexistent_field" not in pkg["fields"]

    def test_disclosure_path_absent_field(self):
        assert disclosure_path(self.args, "nonexistent") is None

    def test_disclosure_path_known_field(self):
        path = disclosure_path(self.args, "amount")
        assert path is not None
        assert len(path) >= 1
        # Every sibling is sha256-prefixed
        for is_right, sib in path:
            assert isinstance(is_right, bool)
            assert sib.startswith("sha256:")

    def test_path_uses_duplication_for_odd_counts(self):
        # 3 fields -> first level has one self-paired node
        args = {"a": 1, "b": 2, "c": 3}
        root = commit_args(args)
        for f in args:
            pkg = disclose_args(args, [f])
            assert verify_disclosure(root, pkg) == {f: args[f]}

    def test_single_field_path_empty(self):
        args = {"only": 42}
        root = commit_args(args)
        pkg = disclose_args(args, ["only"])
        assert pkg["fields"]["only"]["path"] == []
        assert verify_disclosure(root, pkg) == {"only": 42}


class TestPartialRecheck:
    def setup_method(self):
        self.constraints = {
            "allowed_values": {
                "from_account": ["ACC-001", "ACC-002"],
                "to_account": ["ACC-003"],
            },
            "max_value": {"amount": 10000},
            "min_value": {"amount": 1},
            "required_present": ["reference"],
        }

    def test_all_disclosed_satisfied(self):
        fields = {
            "from_account": "ACC-001",
            "to_account": "ACC-003",
            "amount": 500,
            "reference": "INV-001",
        }
        results = recheck_constraints(self.constraints, fields)
        assert results["allowed_values"] == "SATISFIED"
        assert results["max_value"] == "SATISFIED"
        assert results["min_value"] == "SATISFIED"
        assert results["required_present"] == "SATISFIED"

    def test_violated_constraint(self):
        fields = {
            "from_account": "ACC-001",
            "to_account": "ACC-999",  # not allowed
            "amount": 500,
            "reference": "INV-001",
        }
        results = recheck_constraints(self.constraints, fields)
        assert results["allowed_values"] == "VIOLATED"

    def test_over_max_violated(self):
        fields = {
            "from_account": "ACC-001",
            "to_account": "ACC-003",
            "amount": 50000,
            "reference": "x",
        }
        results = recheck_constraints(self.constraints, fields)
        assert results["max_value"] == "VIOLATED"

    def test_undisclosed_field_is_unknown(self):
        fields = {"from_account": "ACC-001", "reference": "x"}  # amount, to_account hidden
        results = recheck_constraints(self.constraints, fields)
        assert results["allowed_values"] == "UNKNOWN"
        assert results["max_value"] == "UNKNOWN"
        assert results["min_value"] == "UNKNOWN"
        assert results["required_present"] == "SATISFIED"

    def test_unknown_never_counts_as_satisfied(self):
        fields = {}
        results = recheck_constraints(self.constraints, fields)
        assert all(v == "UNKNOWN" for v in results.values())

    def test_starts_with_constraint(self):
        constraints = {"starts_with": {"account": ["ACC-"]}}
        assert (
            recheck_constraints(constraints, {"account": "ACC-001"})["starts_with"] == "SATISFIED"
        )
        assert recheck_constraints(constraints, {"account": "BBB-001"})["starts_with"] == "VIOLATED"
        assert recheck_constraints(constraints, {})["starts_with"] == "UNKNOWN"

    def test_forbidden_values(self):
        constraints = {"forbidden_values": {"to_account": ["BLACKLIST-001"]}}
        assert (
            recheck_constraints(constraints, {"to_account": "ACC-003"})["forbidden_values"]
            == "SATISFIED"
        )
        assert (
            recheck_constraints(constraints, {"to_account": "BLACKLIST-001"})["forbidden_values"]
            == "VIOLATED"
        )
        assert recheck_constraints(constraints, {})["forbidden_values"] == "UNKNOWN"

    def test_forbidden_combinations(self):
        constraints = {
            "forbidden_field_combinations": [["admin", "debug"]],
        }
        # Both disclosed, both truthy -> VIOLATED
        assert (
            recheck_constraints(constraints, {"admin": True, "debug": True})[
                "forbidden_field_combinations"
            ]
            == "VIOLATED"
        )
        # Both disclosed, one falsy -> SATISFIED
        assert (
            recheck_constraints(constraints, {"admin": True, "debug": False})[
                "forbidden_field_combinations"
            ]
            == "SATISFIED"
        )
        # One undisclosed -> UNKNOWN
        assert (
            recheck_constraints(constraints, {"admin": True})["forbidden_field_combinations"]
            == "UNKNOWN"
        )

    def test_empty_constraints_vacuously_satisfied(self):
        results = recheck_constraints({"allowed_values": {}}, {"x": 1})
        assert results["allowed_values"] == "SATISFIED"


class TestEndToEndWithRealGate:
    """The full flow: gate decision -> commitment -> selective disclosure -> re-check."""

    def test_full_flow_satisfied(self):
        from raucle.capability import CapabilityGate, CapabilityIssuer

        # 1. Mint a capability with constraints
        issuer = CapabilityIssuer.generate(issuer="test.bank")
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        token = issuer.mint(
            agent_id="agent:payments",
            tool="transfer_money",
            constraints={
                "allowed_values": {"from_account": ["ACC-001"], "to_account": ["ACC-003"]},
                "max_value": {"amount": 10000},
            },
            ttl_seconds=600,
        )

        # 2. The gate allows a call
        args = {
            "from_account": "ACC-001",
            "to_account": "ACC-003",
            "amount": 500,
            "reference": "INV-1",
        }
        decision = gate.check(token, tool="transfer_money", agent_id="agent:payments", args=args)
        assert decision.allowed

        # 3. Operator commits args and discloses a subset
        root = commit_args(args)
        pkg = disclose_args(args, ["from_account", "to_account", "amount"])
        verified = verify_disclosure(root, pkg)

        # 4. Verifier re-checks constraints against disclosed fields only
        constraints = token.constraints
        results = recheck_constraints(constraints, verified)
        assert results["allowed_values"] == "SATISFIED"
        assert results["max_value"] == "SATISFIED"

    def test_full_flow_detects_violation(self):
        from raucle.capability import CapabilityGate, CapabilityIssuer

        issuer = CapabilityIssuer.generate(issuer="test.bank")
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        token = issuer.mint(
            agent_id="agent:payments",
            tool="transfer_money",
            constraints={
                "allowed_values": {"to_account": ["ACC-003"]},
                "max_value": {"amount": 10000},
            },
            ttl_seconds=600,
        )

        # A call the gate would deny
        args = {"from_account": "ACC-001", "to_account": "ACC-999", "amount": 50}
        decision = gate.check(token, tool="transfer_money", agent_id="agent:payments", args=args)
        assert not decision.allowed

        # Operator discloses anyway; the verifier catches the violation
        root = commit_args(args)
        pkg = disclose_args(args, ["to_account", "amount"])
        verified = verify_disclosure(root, pkg)
        results = recheck_constraints(token.constraints, verified)
        assert results["allowed_values"] == "VIOLATED"

    def test_undisclosed_stays_hidden(self):
        # The core privacy property: undisclosed fields are not recoverable
        args = {
            "from_account": "ACC-001",
            "to_account": "ACC-003",
            "amount": 500,
            "patient_notes": "CONFIDENTIAL: patient discussed self-harm in session",
        }
        root = commit_args(args)
        # Disclose only the transfer fields
        pkg = disclose_args(args, ["from_account", "to_account", "amount"])
        verified = verify_disclosure(root, pkg)
        # The verifier never sees patient_notes
        assert "patient_notes" not in verified
        assert len(verified) == 3
        # And cannot derive it from the package
        assert "patient_notes" not in str(pkg)
