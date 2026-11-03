"""Utility di benchmark compatto per raccogliere misure di durata e dimensione messaggi."""

from __future__ import annotations

import contextlib
import statistics
import time
from collections import defaultdict
from typing import Iterator

from crypto.crypto_utils import json_size


class MetricsCollector:
    def __init__(self) -> None:
        # Dizionario che tiene traccia, per ogni "nome di operazione", della lista delle durate (in secondi, float)
        self.timings: dict[str, list[float]] = defaultdict(list)
        # Dizionario che tiene traccia, per ogni "nome di operazione", della lista delle dimensioni messaggi (int, in byte JSON)
        self.sizes: dict[str, list[int]] = defaultdict(list)

    @contextlib.contextmanager
    def measure(self, name: str) -> Iterator[None]:
        """
        Context manager per misurare il tempo di esecuzione di un blocco di codice.
        Esempio d'uso:
            with metrics.measure("esempio"):
                ... codice da misurare ...
        Alla fine del blocco, salva la durata in self.timings[name].
        """
        start = time.perf_counter()  # Prende il tempo di partenza ad alta risoluzione
        try:
            yield  # Consente l'esecuzione del blocco utente dentro il contesto
        finally:
            # Alla fine del blocco, calcola la durata e la aggiunge nella lista delle misure per il nome
            self.timings[name].append(time.perf_counter() - start)

    def add_time(self, name: str, duration: float) -> None:
        """
        Aggiunge manualmente una misura di durata (in secondi) sotto il nome specificato.
        Utile per misurazioni personalizzate senza usare il context manager.
        """
        self.timings[name].append(duration)

    def add_size(self, name: str, data: object) -> None:
        """
        Calcola la dimensione (in byte JSON serializzato) dell'oggetto passato
        e la salva nella lista self.sizes sotto il nome specificato.
        """
        self.sizes[name].append(json_size(data))

    def total(self, name: str) -> float:
        """
        Restituisce la somma totale delle durate raccolte per il nome.
        Se non ci sono misure, restituisce 0.
        """
        return sum(self.timings.get(name, []))

    def avg(self, name: str) -> float:
        """
        Restituisce la durata media (mean) per il nome misurato.
        Se non ci sono misure, restituisce 0.0 per evitare errori.
        """
        values = self.timings.get(name, [])
        return statistics.mean(values) if values else 0.0

    def avg_size(self, name: str) -> float:
        """
        Restituisce la dimensione media (mean) per i messaggi/sorgenti col nome specificato.
        Se non ci sono elementi, restituisce 0.0 per sicurezza.
        """
        values = self.sizes.get(name, [])
        return statistics.mean(values) if values else 0.0
