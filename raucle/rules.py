"""YAML rule loader for Raucle Detect.

Rule files follow the Raucle rule-pack format:

    rules:
      - id: PI-100
        name: markdown_image_exfil
        category: indirect_injection
        technique: markdown_exfiltration
        severity: HIGH
        patterns:
          - '(?i)...'
        score: 0.80

Files can also be a bare YAML list (without the ``rules:`` wrapper key).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _require_yaml() -> None:
    if not _YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required to load rule files.  "
            "Install it with:  pip install raucle[rules]  or  pip install pyyaml"
        )


_REQUIRED_RULE_FIELDS: set[str] = {"id", "name", "category", "patterns", "score"}
_VALID_SEVERITIES: set[str] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _validate_patterns(prefix: str, patterns: Any) -> list[str]:
    """Validate the ``patterns`` field of a rule."""
    if not isinstance(patterns, list) or not patterns:
        return [f"{prefix}: 'patterns' must be a non-empty list"]

    errors: list[str] = []
    for i, p in enumerate(patterns):
        if not isinstance(p, str):
            errors.append(f"{prefix}: patterns[{i}] must be a string")
            continue
        try:
            import re

            re.compile(p)
        except Exception as exc:
            errors.append(f"{prefix}: patterns[{i}] invalid regex: {exc}")
    return errors


def _validate_score(prefix: str, score: Any) -> list[str]:
    """Validate the ``score`` field of a rule."""
    if score is not None and not isinstance(score, (int, float)):
        return [f"{prefix}: 'score' must be a number, got {type(score).__name__}"]
    if score is not None and not (0.0 <= float(score) <= 1.0):
        return [f"{prefix}: 'score' must be between 0.0 and 1.0, got {score}"]
    return []


def _validate_rule(rule: Any, source: str) -> list[str]:
    """Return a list of validation error strings for *rule*, or empty list if valid."""
    if not isinstance(rule, dict):
        return [f"{source}: rule must be a mapping, got {type(rule).__name__}"]

    errors: list[str] = []
    rule_id = rule.get("id", "<unknown>")
    prefix = f"{source}[{rule_id}]"

    missing = _REQUIRED_RULE_FIELDS - rule.keys()
    if missing:
        errors.append(f"{prefix}: missing required fields: {sorted(missing)}")

    patterns = rule.get("patterns")
    if patterns is not None:
        errors.extend(_validate_patterns(prefix, patterns))

    errors.extend(_validate_score(prefix, rule.get("score")))

    severity = rule.get("severity")
    if severity is not None and severity not in _VALID_SEVERITIES:
        errors.append(
            f"{prefix}: 'severity' must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
        )

    return errors


def load_yaml_file(path: str | Path) -> list[dict[str, Any]]:
    """Load rules from a single YAML file and return a list of validated rule dicts."""
    _require_yaml()
    path = Path(path)

    with open(path) as fh:
        data = yaml.safe_load(fh)

    if isinstance(data, list):
        raw_rules = data
    elif isinstance(data, dict) and "rules" in data:
        raw_rules = data["rules"]
    else:
        raise ValueError(f"Unrecognised rule file format in {path}")

    valid_rules: list[dict[str, Any]] = []
    for rule in raw_rules:
        errors = _validate_rule(rule, str(path))
        if errors:
            for err in errors:
                logger.exception("Rule validation error: %s", err)
        else:
            valid_rules.append(rule)

    skipped = len(raw_rules) - len(valid_rules)
    if skipped:
        logger.warning("Skipped %d invalid rule(s) from %s", skipped, path)

    return valid_rules


def load_rules_dir(directory: str | Path) -> list[dict[str, Any]]:
    """Load all ``*.yaml`` and ``*.yml`` files from *directory*.

    Returns the concatenated list of rules.  Files are loaded in sorted order
    so that rule precedence is deterministic.
    """
    _require_yaml()
    directory = Path(directory)
    rules: list[dict[str, Any]] = []

    if not directory.is_dir():
        logger.warning("Rules directory does not exist: %s", directory)
        return rules

    for rule_file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        try:
            rules.extend(load_yaml_file(rule_file))
            logger.info("Loaded %s", rule_file.name)
        except Exception as exc:
            logger.exception("Failed to load %s: %s", rule_file, exc)

    return rules


def list_loaded_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a compact summary suitable for display or serialisation."""
    return [
        {
            "id": r.get("id", "?"),
            "name": r.get("name", "unnamed"),
            "category": r.get("category", ""),
            "severity": r.get("severity", "MEDIUM"),
            "pattern_count": len(r.get("patterns", [])),
            "score": r.get("score", 0.5),
        }
        for r in rules
    ]
