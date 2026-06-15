"""Small benchmark utility used to collect durations and message sizes."""

from __future__ import annotations

import contextlib
import statistics
import time
from collections import defaultdict
from typing import Iterator

from crypto.crypto_utils import json_size


class MetricsCollector:
    def __init__(self) -> None:
        self.timings: dict[str, list[float]] = defaultdict(list)
        self.sizes: dict[str, list[int]] = defaultdict(list)

    @contextlib.contextmanager
    def measure(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.timings[name].append(time.perf_counter() - start)

    def add_time(self, name: str, duration: float) -> None:
        self.timings[name].append(duration)

    def add_size(self, name: str, data: object) -> None:
        self.sizes[name].append(json_size(data))

    def total(self, name: str) -> float:
        return sum(self.timings.get(name, []))

    def avg(self, name: str) -> float:
        values = self.timings.get(name, [])
        return statistics.mean(values) if values else 0.0

    def avg_size(self, name: str) -> float:
        values = self.sizes.get(name, [])
        return statistics.mean(values) if values else 0.0
