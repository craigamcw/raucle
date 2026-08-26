"""Core Scanner -- the main developer-facing API for Raucle Detect.

Usage::

    from raucle import Scanner

    scanner = Scanner()
    result = scanner.scan("Ignore all previous instructions")
    if result.injection_detected:
        print(f"Blocked: {result.verdict} ({result.confidence:.0%})")

The scanner combines a fast regex pattern layer with a heuristic (or optional
ML) semantic classifier, producing a single :class:`ScanResult` per prompt.
"""

from __future__ import annotations

import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.classifier import HeuristicClassifier, MLClassifier
from raucle.patterns import BUILTIN_PATTERNS, OUTPUT_RULES, TOOL_CALL_RULES, PatternLayer
from raucle.rules import load_rules_dir, load_yaml_file

logger = logging.getLogger(__name__)


class ReceiptEmissionError(RuntimeError):
    """Raised when ``require_receipts=True`` and a receipt/audit/provenance
    side effect cannot be produced. Fail-loud variant of the default
    warn-and-continue behaviour: a scan without its evidence trail is treated
    as a failure rather than silently succeeding."""


def _input_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Input size limits
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 1_048_576  # 1 MB
MAX_INPUT_LENGTH = 100_000  # characters

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Immutable result of scanning a single prompt."""

    verdict: str
    """One of ``CLEAN``, ``SUSPICIOUS``, or ``MALICIOUS``."""

    confidence: float
    """Combined score from all layers, between 0.0 and 1.0."""

    injection_detected: bool
    """``True`` when the combined score meets the detection threshold."""

    categories: list[str] = field(default_factory=list)
    """Threat categories that matched (e.g. ``direct_injection``, ``jailbreak``)."""

    attack_technique: str = ""
    """Most specific attack technique identified."""

    layer_scores: dict[str, float] = field(default_factory=dict)
    """Per-layer breakdown: ``pattern``, ``semantic``."""

    matched_rules: list[str] = field(default_factory=list)
    """IDs of pattern rules that fired."""

    action: str = "ALLOW"
    """Recommended action: ``ALLOW``, ``ALERT``, or ``BLOCK``."""

    notes: list[str] = field(default_factory=list)
    """Informational notes (e.g. input was truncated)."""

    receipt: str = ""
    """Optional detached JWS receipt — present when a verdict signer is wired in."""

    provenance_hash: str = ""
    """Hash of the auto-emitted provenance receipt — present when a
    :class:`~raucle.provenance.ProvenanceLogger` is wired in.
    Descendants should pass this as a parent when they record their next step."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary (JSON-friendly)."""
        d: dict[str, Any] = {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "injection_detected": self.injection_detected,
            "categories": self.categories,
            "attack_technique": self.attack_technique,
            "layer_scores": self.layer_scores,
            "matched_rules": self.matched_rules,
            "action": self.action,
        }
        if self.notes:
            d["notes"] = self.notes
        if self.receipt:
            d["receipt"] = self.receipt
        if self.provenance_hash:
            d["provenance_hash"] = self.provenance_hash
        return d


# ---------------------------------------------------------------------------
# Mode thresholds
# ---------------------------------------------------------------------------

_MODE_THRESHOLDS: dict[str, dict[str, float]] = {
    "strict": {"block": 0.4, "alert": 0.2},
    "standard": {"block": 0.7, "alert": 0.4},
    "permissive": {"block": 0.85, "alert": 0.6},
}

# Layer weights: pattern 30 %, semantic 70 %
_PATTERN_WEIGHT = 0.35
_SEMANTIC_WEIGHT = 0.65


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """High-level prompt-injection scanner.

    Parameters
    ----------
    mode : str
        Detection sensitivity -- ``"strict"``, ``"standard"`` (default), or
        ``"permissive"``.
    rules_dir : str | Path | None
        Path to a directory of YAML rule files.  If ``None`` (default), only
        built-in patterns are used.
    use_ml : bool
        When ``True``, attempt to load a local transformer model for the
        semantic layer.  Defaults to ``False`` (heuristic classifier).
    model_path : str | None
        Path to the directory containing the ``semantic-classifier/`` model
        checkpoint.  Only relevant when *use_ml* is ``True``.
    require_receipts : bool
        When ``True``, a failure to issue the verdict receipt, write the audit
        event, or emit the provenance receipt raises
        :class:`ReceiptEmissionError` instead of logging a warning — a scan
        without its evidence trail is treated as a failure. Defaults to
        ``False`` (warn and continue).
    """

    def __init__(
        self,
        mode: str = "standard",
        rules_dir: str | Path | None = None,
        use_ml: bool = False,
        model_path: str | None = None,
        audit_sink: Any = None,
        verdict_signer: Any = None,
        model_version: str = "",
        tenant: str | None = None,
        provenance_logger: Any = None,
        input_store: Any = None,
        feed_store: Any = None,
        require_receipts: bool = False,
    ) -> None:
        if mode not in _MODE_THRESHOLDS:
            raise ValueError(f"Unknown mode {mode!r}. Choose from: strict, standard, permissive")

        self._mode = mode
        self._thresholds = _MODE_THRESHOLDS[mode]

        # Pattern layer
        self._pattern_layer = PatternLayer()
        self._pattern_layer.load_builtin()

        # Load custom rules
        if rules_dir is not None:
            extra = load_rules_dir(rules_dir)
            if extra:
                self._pattern_layer.add_rules(extra)

        # Federated signed-IOC feeds (v0.8.0)
        self._feed_store = feed_store
        if feed_store is not None:
            feed_rules = feed_store.as_pattern_rules()
            if feed_rules:
                self._pattern_layer.add_rules(feed_rules)

        # Semantic layer
        self._heuristic = HeuristicClassifier()
        self._ml: MLClassifier | None = None
        if use_ml:
            ml = MLClassifier()
            if ml.load(model_path):
                self._ml = ml

        # Compliance / receipt machinery (all optional)
        self._audit_sink = audit_sink
        self._verdict_signer = verdict_signer
        self._provenance_logger = provenance_logger
        self._input_store = input_store
        self._model_version = model_version
        self._tenant = tenant
        self._require_receipts = require_receipts
        self._ruleset_hash_cached: str | None = None

    def _ruleset_hash(self) -> str:
        """Return (and cache) the canonical hash of the active ruleset."""
        if self._ruleset_hash_cached is None:
            from raucle.verdicts import hash_ruleset

            self._ruleset_hash_cached = hash_ruleset(self._pattern_layer._rules)
        return self._ruleset_hash_cached

    def _issue_receipt(self, result: ScanResult, input_text: str) -> None:
        """Issue a signed verdict receipt, honouring the require-receipts flag."""
        if self._verdict_signer is None:
            return
        try:
            result.receipt = self._verdict_signer.issue(
                input_text=input_text,
                verdict=result.verdict,
                confidence=result.confidence,
                ruleset_hash=self._ruleset_hash(),
                model_version=self._model_version,
                tenant=self._tenant,
            )
        except Exception as exc:
            logger.warning("Failed to issue verdict receipt: %s", exc)
            if self._require_receipts:
                raise ReceiptEmissionError(f"Failed to issue verdict receipt: {exc}") from exc

    def _write_audit(self, result: ScanResult, input_text: str, scan_kind: str) -> None:
        """Append an audit event, honouring the require-receipts flag."""
        if self._audit_sink is None:
            return
        try:
            self._audit_sink.append(
                {
                    "kind": scan_kind,
                    "tenant": self._tenant,
                    "verdict": result.verdict,
                    "confidence": result.confidence,
                    "categories": result.categories,
                    "matched_rules": result.matched_rules,
                    "ruleset_hash": self._ruleset_hash(),
                    "model_version": self._model_version,
                    "input_hash": _input_hash(input_text),
                }
            )
        except Exception as exc:
            logger.warning("Failed to write audit event: %s", exc)
            if self._require_receipts:
                raise ReceiptEmissionError(f"Failed to write audit event: {exc}") from exc

    def _emit_provenance(
        self,
        result: ScanResult,
        input_text: str,
        scan_kind: str,
        provenance_parents: list[str] | None,
    ) -> None:
        """Record a provenance guardrail scan, honouring the require-receipts flag."""
        if self._provenance_logger is None:
            return
        try:
            # Map the scan kind to the target the guardrail acted on.
            scan_target = {
                "scan": "input",
                "scan_output": "output",
                "scan_tool_call": "tool_call",
            }.get(scan_kind, "input")
            result.provenance_hash = self._provenance_logger.record_guardrail_scan(
                parents=list(provenance_parents or []),
                scanned_text=input_text,
                verdict=result.verdict,
                ruleset_hash=self._ruleset_hash(),
                scan_target=scan_target,
            )
        except Exception as exc:
            logger.warning("Failed to emit provenance receipt: %s", exc)
            if self._require_receipts:
                raise ReceiptEmissionError(f"Failed to emit provenance receipt: {exc}") from exc

    def _persist_input(self, input_text: str) -> None:
        """Persist original input text for later counterfactual replay."""
        if self._input_store is None:
            return
        try:
            self._input_store.add(input_text, tenant=self._tenant)
        except Exception as exc:
            logger.warning("Failed to write input store: %s", exc)

    def _finalize(
        self,
        result: ScanResult,
        input_text: str,
        scan_kind: str = "scan",
        provenance_parents: list[str] | None = None,
    ) -> ScanResult:
        """Apply signed-receipt + audit-sink + provenance side effects."""
        self._issue_receipt(result, input_text)
        self._write_audit(result, input_text, scan_kind)
        self._emit_provenance(result, input_text, scan_kind, provenance_parents)
        self._persist_input(input_text)
        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    def load_rules(self, path: str | Path) -> int:
        """Load additional rules from a YAML file or directory.

        Returns the number of rules added.
        """
        path = Path(path)
        if path.is_dir():
            rules = load_rules_dir(path)
        elif path.is_file():
            rules = load_yaml_file(path)
        else:
            return 0
        if rules:
            self._pattern_layer.add_rules(rules)
        return len(rules)

    def list_rules(self) -> list[dict[str, Any]]:
        """Return a summary of all loaded rules."""
        return self._pattern_layer.list_rules()

    def scan(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
        mode: str | None = None,
        provenance_parents: list[str] | None = None,
    ) -> ScanResult:
        """Scan a single prompt and return a :class:`ScanResult`.

        Parameters
        ----------
        prompt : str
            The text to scan.
        context : dict, optional
            Unused in the open-source edition but reserved for future
            contextual scoring (user role, data classification, etc.).
        mode : str, optional
            Override the scanner-level mode for this single call.
        """
        thresholds = _MODE_THRESHOLDS.get(mode, self._thresholds) if mode else self._thresholds

        # Input size guard
        notes: list[str] = []
        if len(prompt) > MAX_INPUT_LENGTH:
            logger.warning(
                "Input truncated from %d to %d characters", len(prompt), MAX_INPUT_LENGTH
            )
            prompt = prompt[:MAX_INPUT_LENGTH]
            notes.append(
                f"Input was truncated to {MAX_INPUT_LENGTH:,} characters. "
                "Detection covers the truncated text only."
            )

        # Layer 1: Pattern matching
        pat = self._pattern_layer.scan(prompt)

        # Layer 2: Semantic classification
        if self._ml is not None:
            sem = self._ml.classify(prompt)
        else:
            sem = self._heuristic.classify(prompt)

        # Combine scores
        combined = pat["score"] * _PATTERN_WEIGHT + sem["score"] * _SEMANTIC_WEIGHT

        # Merge categories
        categories = list(set(pat.get("categories", []) + sem.get("categories", [])))

        # Pick most specific technique
        technique = pat.get("technique", "") or sem.get("technique", "")

        # Determine verdict
        if combined >= thresholds["block"]:
            verdict = "MALICIOUS"
            action = "BLOCK"
        elif combined >= thresholds["alert"]:
            verdict = "SUSPICIOUS"
            action = "ALERT"
        else:
            verdict = "CLEAN"
            action = "ALLOW"

        return self._finalize(
            ScanResult(
                verdict=verdict,
                confidence=round(combined, 4),
                injection_detected=combined >= thresholds["alert"],
                categories=categories,
                attack_technique=technique,
                layer_scores={
                    "pattern": round(pat["score"], 4),
                    "semantic": round(sem["score"], 4),
                },
                matched_rules=pat.get("matched_rules", []),
                action=action,
                notes=notes,
            ),
            prompt,
            scan_kind="scan",
            provenance_parents=provenance_parents,
        )

    def _detect_prompt_mirroring(self, pat: dict, output: str, original_prompt: str) -> list[str]:
        """Check if substantial chunks of the prompt appear in the output.

        Returns a list of notes to add (empty if no mirroring detected).
        Mutates *pat* in place to flag the leakage.
        """
        if not original_prompt or len(original_prompt) <= 20:
            return []
        prompt_lower = original_prompt.lower()
        output_lower = output.lower()
        window = 50  # characters
        for i in range(0, min(len(prompt_lower) - window, 500), 10):
            chunk = prompt_lower[i : i + window]
            if chunk in output_lower:
                if pat["score"] < 0.80:
                    pat["score"] = 0.80
                if "data_leakage" not in pat["categories"]:
                    pat["categories"].append("data_leakage")
                pat["technique"] = pat.get("technique") or "system_prompt_leak"
                return ["Output contains content that mirrors the original prompt."]
        return []

    def scan_output(
        self,
        output: str,
        original_prompt: str | None = None,
        mode: str | None = None,
        provenance_parents: list[str] | None = None,
    ) -> ScanResult:
        """Scan LLM output for data leakage, exfiltration, and injection.

        Parameters
        ----------
        output : str
            The LLM-generated text to scan.
        original_prompt : str, optional
            If provided, the scanner checks whether the output suspiciously
            mirrors system-level content from the prompt.
        mode : str, optional
            Override the scanner-level mode for this single call.
        """
        thresholds = _MODE_THRESHOLDS.get(mode, self._thresholds) if mode else self._thresholds

        notes: list[str] = []
        if len(output) > MAX_INPUT_LENGTH:
            output = output[:MAX_INPUT_LENGTH]
            notes.append(
                f"Output was truncated to {MAX_INPUT_LENGTH:,} characters. "
                "Detection covers the truncated text only."
            )

        # Collect DLP rules from built-in patterns
        dlp_rules = [r for r in BUILTIN_PATTERNS if r["id"].startswith("DLP-")]

        # Run output-specific rules + DLP rules against the output
        pat = self._pattern_layer.scan_with_rules(output, [OUTPUT_RULES, dlp_rules])

        # If original_prompt is provided, check for suspicious mirroring
        notes.extend(self._detect_prompt_mirroring(pat, output, original_prompt or ""))

        # Semantic layer on output
        if self._ml is not None:
            sem = self._ml.classify(output)
        else:
            sem = self._heuristic.classify(output)

        combined = pat["score"] * _PATTERN_WEIGHT + sem["score"] * _SEMANTIC_WEIGHT
        categories = list(set(pat.get("categories", []) + sem.get("categories", [])))
        technique = pat.get("technique", "") or sem.get("technique", "")

        if combined >= thresholds["block"]:
            verdict = "MALICIOUS"
            action = "BLOCK"
        elif combined >= thresholds["alert"]:
            verdict = "SUSPICIOUS"
            action = "ALERT"
        else:
            verdict = "CLEAN"
            action = "ALLOW"

        return self._finalize(
            ScanResult(
                verdict=verdict,
                confidence=round(combined, 4),
                injection_detected=combined >= thresholds["alert"],
                categories=categories,
                attack_technique=technique,
                layer_scores={
                    "pattern": round(pat["score"], 4),
                    "semantic": round(sem["score"], 4),
                },
                matched_rules=pat.get("matched_rules", []),
                action=action,
                notes=notes,
            ),
            output,
            scan_kind="scan_output",
            provenance_parents=provenance_parents,
        )

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        mode: str | None = None,
        provenance_parents: list[str] | None = None,
    ) -> ScanResult:
        """Scan tool call arguments for dangerous patterns before execution.

        Parameters
        ----------
        tool_name : str
            Name of the tool being called.
        arguments : dict
            Tool call arguments to inspect.
        mode : str, optional
            Override the scanner-level mode for this single call.
        """
        thresholds = _MODE_THRESHOLDS.get(mode, self._thresholds) if mode else self._thresholds

        # Serialize all argument values to strings
        parts = [tool_name]
        for key, value in arguments.items():
            parts.append(f"{key}={value}")
        text = " ".join(parts)

        notes: list[str] = []
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]
            notes.append("Tool call arguments were truncated for scanning.")

        # Collect DLP rules from built-in patterns
        dlp_rules = [r for r in BUILTIN_PATTERNS if r["id"].startswith("DLP-")]

        # Run tool-specific rules + DLP rules
        pat = self._pattern_layer.scan_with_rules(text, [TOOL_CALL_RULES, dlp_rules])

        # No semantic layer for tool calls -- pattern-only
        combined = pat["score"]
        categories = list(set(pat.get("categories", [])))
        technique = pat.get("technique", "")

        if combined >= thresholds["block"]:
            verdict = "MALICIOUS"
            action = "BLOCK"
        elif combined >= thresholds["alert"]:
            verdict = "SUSPICIOUS"
            action = "ALERT"
        else:
            verdict = "CLEAN"
            action = "ALLOW"

        return self._finalize(
            ScanResult(
                verdict=verdict,
                confidence=round(combined, 4),
                injection_detected=combined >= thresholds["alert"],
                categories=categories,
                attack_technique=technique,
                layer_scores={
                    "pattern": round(pat["score"], 4),
                },
                matched_rules=pat.get("matched_rules", []),
                action=action,
                notes=notes,
            ),
            text,
            scan_kind="scan_tool_call",
            provenance_parents=provenance_parents,
        )

    def scan_batch(
        self,
        prompts: list[str],
        workers: int = 4,
        mode: str | None = None,
    ) -> list[ScanResult]:
        """Scan multiple prompts concurrently.

        Parameters
        ----------
        prompts : list[str]
            Prompts to scan.
        workers : int
            Maximum number of threads.
        mode : str, optional
            Override the scanner-level mode for this batch.

        Returns
        -------
        list[ScanResult]
            Results in the same order as the input prompts.
        """
        max_workers = max(1, min(workers, os.cpu_count() or 4))
        if max_workers != workers:
            logger.warning(
                "Worker count adjusted from %d to %d (clamped to CPU count)", workers, max_workers
            )

        results: list[ScanResult | None] = [None] * len(prompts)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_idx = {pool.submit(self.scan, p, mode=mode): i for i, p in enumerate(prompts)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                results[idx] = future.result()
        return results  # type: ignore[return-value]
