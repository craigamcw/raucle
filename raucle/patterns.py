"""Pattern matching layer -- fast regex-based detection of known injection techniques.

This module provides the first line of defence, scanning prompts against a library
of compiled regular expressions that match known attack signatures. Target latency
is under 1 ms for a typical prompt.
"""

from __future__ import annotations

import logging
import re
import time
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


@lru_cache(maxsize=2048)
def _compile_pattern(pattern: str) -> re.Pattern[str] | None:
    """Compile and cache a regex pattern. Returns None on compile error."""
    try:
        return re.compile(pattern)
    except re.error as exc:
        logger.warning("Invalid regex (cached skip): %s — %s", pattern[:80], exc)
        return None


def _compile_rule_patterns(rule: dict[str, Any]) -> list[tuple[re.Pattern[str] | None, str]]:
    """Compile all patterns for a rule, skipping un-compilable ones.

    Returns a list of ``(compiled, raw_pattern)`` tuples where *compiled*
    is ``None`` for patterns that failed to compile.
    """
    return [(_compile_pattern(p), p) for p in rule.get("patterns", [])]


# ---------------------------------------------------------------------------
# ReDoS protection constants
# ---------------------------------------------------------------------------

MAX_INPUT_LENGTH = 100_000  # characters -- inputs longer than this are truncated

# Defensive per-pattern length cap.
#
# *Every* individual regex is matched against at most this many characters,
# regardless of which pattern it is. Catastrophic-backtracking blowups are a
# function of input length, so bounding the slice each pattern sees turns a
# potential super-linear hang into a bounded, sub-second operation while still
# covering any realistic attack payload (real injections are short and appear
# early in the text). This replaces the old design, which only capped two
# hard-coded patterns and let ~178 others run unguarded against the full input.
_PER_PATTERN_MAX_LENGTH = 10_000

# Hard per-scan wall-clock budget (seconds). A scan touches ~190 patterns; if
# the cumulative time crosses this deadline we stop evaluating further patterns
# and return what we have. This is a belt-and-braces guard so that no single
# scan can monopolise a worker even if a future pattern slips past review.
_SCAN_TIME_BUDGET_S = 0.75

# ---------------------------------------------------------------------------
# Built-in pattern library
# ---------------------------------------------------------------------------
# Each rule has an id, human-readable name, threat category, MITRE-like
# technique label, severity, a list of regex strings, and a base score
# (0.0-1.0) indicating how confident a single match makes us.
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: list[dict[str, Any]] = [
    # -- Direct injection: instruction override --------------------------------
    {
        "id": "PI-001",
        "name": "instruction_override",
        "category": "direct_injection",
        "technique": "instruction_override",
        "severity": "HIGH",
        "patterns": [
            r"(?i)ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)",
            r"(?i)disregard\s+(all\s+)?prior\s+(instructions|context|rules)",
            r"(?i)forget\s+(all\s+)?(your|previous)\s+(instructions|rules|training)",
            r"(?i)override\s+(your\s+)?(system|previous)\s+(prompt|instructions|rules)",
            r"(?i)you\s+are\s+now\s+(a|an)\s+",
            r"(?i)new\s+instructions?:\s+",
            r"(?i)system\s*:\s*you\s+are",
        ],
        "score": 0.85,
    },
    # -- Direct injection: role hijacking --------------------------------------
    {
        "id": "PI-002",
        "name": "role_hijacking",
        "category": "direct_injection",
        "technique": "role_hijacking",
        "severity": "HIGH",
        "patterns": [
            r"(?i)pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+",
            r"(?i)act\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+",
            r"(?i)roleplay\s+as\s+",
            r"(?i)you\s+are\s+DAN",
            r"(?i)jailbreak\s+mode",
            r"(?i)developer\s+mode\s+(enabled|activated|on)",
            r"(?i)enable\s+(unrestricted|unlimited|god)\s+mode",
        ],
        "score": 0.75,
    },
    # -- Jailbreak: DAN and variants -------------------------------------------
    {
        "id": "PI-003",
        "name": "dan_jailbreak",
        "category": "jailbreak",
        "technique": "dan_jailbreak",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)\bDAN\b.*\bdo\s+anything\s+now\b",
            r"(?i)from\s+now\s+on.*two\s+responses",
            r"(?i)simulate\s+.*\bunfiltered\b",
            r"(?i)maximum\s+mode",
            r"(?i)opposite\s+mode",
            r"(?i)anti-?ai\s+mode",
            r"(?i)DUDE\s+mode",
            r"(?i)AIM\s+mode",
        ],
        "score": 0.90,
    },
    # -- Data exfiltration -----------------------------------------------------
    {
        "id": "PI-004",
        "name": "data_exfiltration",
        "category": "data_exfiltration",
        "technique": "data_exfiltration",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(output|print|show|display|reveal|give|tell|dump|paste|type)\s+.{0,15}(system\s+)?(prompt|instructions?|rules|directives?)",
            r"(?i)(show|print|reveal|display)\s+me\s+.{0,10}(system\s+)?(prompt|instructions?)",
            r"(?i)what\s+(is|are|were)\s+your\s+(system\s+)?(prompt|instructions?|rules)",
            r"(?i)repeat\s+(everything|all|the\s+text)\s+(above|before|prior)",
            r"(?i)(copy|paste|echo)\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
            r"(?i)system\s+prompt\s*(verbatim|exactly|word\s+for\s+word|in\s+full)",
        ],
        "score": 0.80,
    },
    # -- Indirect injection: context manipulation ------------------------------
    {
        "id": "PI-005",
        "name": "context_stuffing",
        "category": "indirect_injection",
        "technique": "context_stuffing",
        "severity": "HIGH",
        "patterns": [
            r"(?i)<\|im_start\|>system",
            r"(?i)\[INST\].*\[/INST\]",
            r"(?i)<<SYS>>.*<</SYS>>",
            r"(?i)Human:\s*\n.*\nAssistant:",
            r"\x00+",  # Null bytes
            r"(?i)<!-- .*(ignore|override|new instructions).*-->",
            r"(?i)\[system\]\s*#",
        ],
        "score": 0.85,
    },
    # -- MCP tool poisoning ----------------------------------------------------
    {
        "id": "PI-006",
        "name": "mcp_tool_poisoning",
        "category": "tool_poisoning",
        "technique": "mcp_tool_poisoning",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)tool_description.*ignore.*instructions",
            r"(?i)when\s+called.*execute.*command",
            r"(?i)hidden\s+instruction.*tool",
            r"(?i)override.*tool.*behavior",
        ],
        "score": 0.90,
    },
    # -- Encoding bypass attempts ----------------------------------------------
    {
        "id": "PI-007",
        "name": "encoding_bypass",
        "category": "evasion",
        "technique": "encoding_bypass",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}",
            r"(?i)decode\s+this\s*:\s*[A-Za-z0-9+/=]{20,}",
            r"(?i)hex\s*:\s*[0-9a-fA-F]{20,}",
            r"(?i)rot13\s*:\s*",
            r"(?i)translate\s+from\s+(base64|hex|binary|rot13)",
        ],
        "score": 0.60,
    },
    # -- Credential / secret patterns ------------------------------------------
    {
        "id": "DLP-001",
        "name": "credential_exposure",
        "category": "data_loss",
        "technique": "credential_exposure",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
            r"sk-[A-Za-z0-9]{20,}",  # OpenAI-style keys
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
            r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
            r"(?i)(secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"AKIA[A-Z0-9]{16}",  # AWS access keys
        ],
        "score": 0.70,
    },
    # -- PII patterns (UK / EU focus) ------------------------------------------
    {
        "id": "DLP-002",
        "name": "pii_exposure",
        "category": "data_loss",
        "technique": "pii_exposure",
        "severity": "HIGH",
        "patterns": [
            r"\b[A-Z]{2}\d{6}[A-Z]\b",  # UK National Insurance Number
            r"\b\d{3}\s?\d{4}\s?\d{4}\b",  # NHS Number
            r"\b[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}\b",  # UK Postcode
            r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",  # Credit card
            r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?\d{7,}\b",  # IBAN
        ],
        "score": 0.65,
    },
]


# ---------------------------------------------------------------------------
# Output-specific rules (for scan_output)
# ---------------------------------------------------------------------------

OUTPUT_RULES: list[dict[str, Any]] = [
    {
        "id": "OUT-001",
        "name": "system_prompt_leak",
        "category": "data_leakage",
        "technique": "system_prompt_leak",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(?:my|the)\s+system\s+(?:prompt|instructions?)\s+(?:is|are|says?)",
            r"(?i)(?:here\s+(?:is|are)\s+)?my\s+(?:original|initial|base)\s+instructions?",
            r"(?i)i\s+was\s+(?:told|instructed|programmed|configured)\s+to",
            r"(?i)my\s+(?:rules?|guidelines?|directives?)\s+(?:state|say|are|include)",
        ],
        "score": 0.80,
    },
    {
        "id": "OUT-002",
        "name": "instruction_injection_in_output",
        "category": "indirect_injection",
        "technique": "output_injection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
            r"(?i)(?:you\s+(?:must|should|need\s+to)|please)\s+(?:now\s+)?(?:execute|run|perform)",
            r"(?i)<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]",
        ],
        "score": 0.75,
    },
    {
        "id": "OUT-003",
        "name": "exfiltration_channel",
        "category": "data_exfiltration",
        "technique": "output_exfiltration",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)!\[[^\]]*\]\(https?://[^)]*(?:api[_-]?key|token|secret|password|credential)",
            r"(?i)(?:fetch|curl|wget|requests?\.get)\s*\(\s*['\"]https?://",
            r"(?i)(?:send|post|transmit|exfiltrate)\s+(?:this|the|all)\s+(?:data|information|content)\s+to",
        ],
        "score": 0.85,
    },
]

# ---------------------------------------------------------------------------
# Tool call rules (for scan_tool_call)
# ---------------------------------------------------------------------------

TOOL_CALL_RULES: list[dict[str, Any]] = [
    {
        "id": "TOOL-001",
        "name": "dangerous_shell_command",
        "category": "tool_abuse",
        "technique": "shell_injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|curl.*\|\s*(?:sh|bash))",
            r"(?i)(?:sudo|su\s+-)\s+",
            r"(?i)(?:>\s*/etc/|/dev/(?:sd|null))",
            r"(?i)(?:eval|exec)\s*\(",
        ],
        "score": 0.90,
    },
    {
        "id": "TOOL-002",
        "name": "path_traversal",
        "category": "tool_abuse",
        "technique": "path_traversal",
        "severity": "HIGH",
        "patterns": [
            r"\.\./\.\./",
            r"(?i)(?:/etc/passwd|/etc/shadow|\.env|\.ssh/|id_rsa)",
            r"(?i)%2e%2e%2f|%252e%252e%252f",
        ],
        "score": 0.85,
    },
    {
        "id": "TOOL-003",
        "name": "sql_injection_in_args",
        "category": "tool_abuse",
        "technique": "sql_injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(?:'\s*(?:OR|AND)\s+['\d]|;\s*DROP\s+TABLE|UNION\s+SELECT|--\s*$)",
            r"(?i)(?:INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM)\s+(?!.*\bWHERE\b)",
        ],
        "score": 0.85,
    },
    {
        "id": "TOOL-004",
        "name": "ssrf_attempt",
        "category": "tool_abuse",
        "technique": "ssrf",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
            r"(?i)(?:file://|gopher://|dict://|ftp://(?:localhost|127))",
        ],
        "score": 0.80,
    },
]


class PatternLayer:
    """Fast regex-based pattern matching layer.

    Compiles all patterns once at load time, then scans incoming text in a
    single pass through the rule list.  Returns the highest-scoring match
    along with the union of matched categories and rule IDs.
    """

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._compiled: list[tuple[dict[str, Any], list[tuple[re.Pattern[str], str]]]] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_builtin(self) -> None:
        """Load only the built-in pattern library (no disk I/O)."""
        self._rules = list(BUILTIN_PATTERNS)
        self._compile()

    def add_rules(self, rules: list[dict[str, Any]]) -> None:
        """Append additional rules (e.g. from YAML) and recompile."""
        self._rules.extend(rules)
        self._compile()

    def _compile(self) -> None:
        self._compiled = []
        for rule in self._rules:
            compiled_patterns: list[tuple[re.Pattern[str], str]] = []
            for p in rule.get("patterns", []):
                compiled = _compile_pattern(p)
                if compiled is not None:
                    compiled_patterns.append((compiled, p))
                else:
                    logger.warning("Skipping invalid regex in rule %s", rule.get("id", "?"))
            self._compiled.append((rule, compiled_patterns))

    # ------------------------------------------------------------------
    # ReDoS-safe matching
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_match(pattern: re.Pattern[str], raw_pattern: str, text: str) -> re.Match[str] | None:
        """Match *pattern* against a length-bounded slice of *text*.

        The slice cap is applied to **every** pattern (not a hard-coded subset),
        so no single regex can be driven into catastrophic backtracking by an
        oversized input. ``raw_pattern`` is retained for signature compatibility
        and future per-pattern tuning.
        """
        if len(text) > _PER_PATTERN_MAX_LENGTH:
            text = text[:_PER_PATTERN_MAX_LENGTH]
        return pattern.search(text)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(self, text: str) -> dict[str, Any]:
        """Scan *text* against all compiled patterns.

        Returns a dict with ``score``, ``categories``, ``technique``, and
        ``matched_rules``.
        """
        # Global input length guard
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]

        best_score = 0.0
        matched_categories: list[str] = []
        matched_technique = ""
        matched_rules: list[str] = []

        deadline = time.monotonic() + _SCAN_TIME_BUDGET_S
        budget_exceeded = False

        for rule, patterns in self._compiled:
            if time.monotonic() > deadline:
                budget_exceeded = True
                break
            for pattern, raw_pattern in patterns:
                if self._safe_match(pattern, raw_pattern, text):
                    score = rule.get("score", 0.5)
                    if score > best_score:
                        best_score = score
                        matched_technique = rule.get("technique", "")
                    matched_categories.append(rule["category"])
                    matched_rules.append(rule["id"])
                    break  # One match per rule is sufficient

        if budget_exceeded:
            logger.warning(
                "Pattern scan exceeded %.2fs budget; stopped early after %d rule(s)",
                _SCAN_TIME_BUDGET_S,
                len(matched_rules),
            )

        return {
            "score": best_score,
            "categories": list(set(matched_categories)),
            "technique": matched_technique,
            "matched_rules": matched_rules,
        }

    def _try_rule(
        self,
        rule: dict[str, Any],
        compiled_patterns: list[tuple[Any, str]],
        text: str,
    ) -> tuple[float, str, str] | None:
        """Try matching one rule's compiled patterns against *text*.

        Returns ``(score, technique, category)`` if the rule matched, else ``None``.
        """
        for compiled, raw in compiled_patterns:
            if compiled is None:
                continue
            if self._safe_match(compiled, raw, text):
                return rule.get("score", 0.5), rule.get("technique", ""), rule["category"]
        return None

    def scan_with_rules(self, text: str, rule_lists: list[list[dict[str, Any]]]) -> dict[str, Any]:
        """Scan *text* against specific rule lists (not the loaded rules).

        Compiles the provided rules on the fly and scans against them.
        Returns the same dict shape as :meth:`scan`.
        """
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]

        best_score = 0.0
        matched_categories: list[str] = []
        matched_technique = ""
        matched_rules: list[str] = []

        deadline = time.monotonic() + _SCAN_TIME_BUDGET_S

        for rule_list in rule_lists:
            for rule in rule_list:
                if time.monotonic() > deadline:
                    logger.warning(
                        "Pattern scan (scan_with_rules) exceeded time budget; stopped early"
                    )
                    return {
                        "score": best_score,
                        "categories": list(set(matched_categories)),
                        "technique": matched_technique,
                        "matched_rules": matched_rules,
                    }
                compiled_patterns = _compile_rule_patterns(rule)
                match = self._try_rule(rule, compiled_patterns, text)
                if match:
                    score, technique, category = match
                    if score > best_score:
                        best_score = score
                        matched_technique = technique
                    matched_categories.append(category)
                    matched_rules.append(rule["id"])

        return {
            "score": best_score,
            "categories": list(set(matched_categories)),
            "technique": matched_technique,
            "matched_rules": matched_rules,
        }

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def list_rules(self) -> list[dict[str, Any]]:
        """Return a summary of every loaded rule."""
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "category": r["category"],
                "severity": r.get("severity", "MEDIUM"),
                "pattern_count": len(r.get("patterns", [])),
            }
            for r in self._rules
        ]
