"""Configuration constants for the WP4 e-voting Proof of Concept."""

from __future__ import annotations

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
HASH_ALGORITHM_NAME = "SHA-256"


DEFAULT_ELECTION_ID = "ELECTION-NATIONAL-REFERENDUM-2026"
ELECTION_TYPE = "REFERENDUM"
DEFAULT_OPTIONS = ("YES", "NO")


TOKEN_VALIDITY_SECONDS = 60 * 60
CERT_VALIDITY_SECONDS = 60 * 60 * 24
FRESHNESS_WINDOW_SECONDS = 5 * 60 #5 minuti

SCRUTINY_NODES = 5
SCRUTINY_THRESHOLD = 3

BENCHMARK_VOTER_COUNTS = (10, 100, 500, 1000)
BENCHMARK_CSV = "benchmark_results.csv"

# A fixed role vocabulary keeps certificate checks explicit and simple.
ROLE_GA = "GA"
ROLE_VS = "VS"
ROLE_ER = "ER"
ROLE_SA = "SA"
ROLE_SA_NODE = "SA_NODE"
