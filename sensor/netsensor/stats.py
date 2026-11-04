"""Counters for everything the extractor skipped, repaired or could not read."""

from collections import Counter
from typing import Dict


class Stats:
    def __init__(self) -> None:
        self._counts: Counter = Counter()

    def add(self, key: str, n: int = 1) -> None:
        self._counts[key] += n

    def get(self, key: str) -> int:
        return self._counts.get(key, 0)

    def as_dict(self) -> Dict[str, int]:
        # Sorted so the stats file is byte-identical across runs.
        return dict(sorted(self._counts.items()))
