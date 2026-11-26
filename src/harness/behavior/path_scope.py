"""Stable path-scope boundaries for the controlled execution environment."""
from __future__ import annotations


# The submitted executable is staged beneath this root in the controlled sandbox.
CONTROLLED_SAMPLE_ROOTS = (r"c:\analyst",)


def is_controlled_sample_path(path: str) -> bool:
    """Return whether a path is the controlled staging root or one of its children."""
    normalized_path = str(path or "").casefold().replace("/", "\\")
    return any(
        normalized_path == root or normalized_path.startswith(root + "\\")
        for root in CONTROLLED_SAMPLE_ROOTS
    )
