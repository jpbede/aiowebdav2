"""Helpers for the tests."""

from pathlib import Path


def load_responses(filename: str) -> str:
    """Load a responses."""
    path = Path(__file__).parent / "responses" / filename
    return path.read_text()
