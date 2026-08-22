"""Shared path validation helper.

Provides :func:`validate_path` for filesystem entry points that accept
caller-supplied paths, satisfying SonarQube ``pythonsecurity:S8707``.
"""

from __future__ import annotations

from pathlib import Path


def validate_path(path: str | Path, *, must_exist: bool = True) -> Path:
    """Resolve and validate a filesystem path before use.

    Args:
        path: The path to validate.
        must_exist: If ``True``, raise when the resolved path does not exist.

    Returns:
        The resolved :class:`~pathlib.Path`.

    Raises:
        ValueError: If *path* is empty or does not exist when required.
    """
    if not path:
        raise ValueError("path must not be empty")
    resolved = Path(path).resolve()
    if must_exist and not resolved.exists():
        raise ValueError(f"path does not exist: {resolved}")
    return resolved
