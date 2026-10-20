"""Append-only JSONL storage for normalized events and policy decisions."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping


class StorageError(RuntimeError):
    """Raised when an incident record cannot be persisted."""


class IncidentStore:
    """Persist common incident records without silently dropping failures."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: Mapping[str, Any]) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(dict(record), sort_keys=True, default=self._serialize) + "\n"
                )
                handle.flush()
        except OSError as exc:
            raise StorageError(f"Unable to append incident record to {self.path}") from exc

    @staticmethod
    def _serialize(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(f"Unsupported incident value: {type(value).__name__}")
