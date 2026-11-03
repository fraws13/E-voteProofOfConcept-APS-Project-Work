"""Configuration constants for the WP4 e-voting Proof of Concept."""

from __future__ import annotations

# Dimensione delle chiavi RSA generate per ogni attore del sistema (in bit)
RSA_KEY_SIZE = 2048  # standard di sicurezza accettato

# Esponente pubblico utilizzato per la generazione di chiavi RSA
RSA_PUBLIC_EXPONENT = 65537

# Algoritmo di hash utilizzato per firme e hash (SHA-256)
HASH_ALGORITHM_NAME = "SHA-256"

# Identificativo di default per l'elezione simulata
DEFAULT_ELECTION_ID = "ELECTION-NATIONAL-REFERENDUM-2026"

# Tipo di elezione (ad es. referendum, elezioni politiche, ecc.)
ELECTION_TYPE = "REFERENDUM"

# Opzioni di voto disponibili nella preferenza (tipicamente SI/NO)
DEFAULT_OPTIONS = ("YES", "NO")

# Tempo di validità di un token di voto in secondi (1 ora)
TOKEN_VALIDITY_SECONDS = 60 * 60

# Tempo di validità dei certificati in secondi (24 ore)
CERT_VALIDITY_SECONDS = 60 * 60 * 24

# Finestra d'accettazione per richieste "fresche", utile per ridurre replay attack (5 minuti)
FRESHNESS_WINDOW_SECONDS = 5 * 60  # 5 minuti

# Numero totale di nodi di scrutinio (per verifica distribuita del risultato)
SCRUTINY_NODES = 5

# Soglia di nodi di scrutinio richiesta per la validazione (rapporto di fiducia)
SCRUTINY_THRESHOLD = 3

# Diverse taglie di elettorato per i benchmark di performance (numero di votanti)
BENCHMARK_VOTER_COUNTS = (10, 100, 500, 1000)

# Nome e percorso file CSV di output dei benchmark
BENCHMARK_CSV = "benchmark_results.csv"

# Vocabolario fisso dei ruoli, utile per firme/certificati e per rendere esplicito il flusso nell'infrastruttura.
ROLE_GA = "GA"           # Government Authority (autorità centrale)
ROLE_VS = "VS"           # Voting Server (server di raccolta voti)
ROLE_ER = "ER"           # Electoral Register (registro elettorale)
ROLE_SA = "SA"           # Scrutiny Authority (autorità di scrutinio)
ROLE_SA_NODE = "SA_NODE" # Nodo di scrutinio (per scrutinio distribuito)
