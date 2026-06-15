# WP4 - E-voting Proof of Concept

Questa repository contiene una Proof of Concept stand-alone in Python del protocollo di voto elettronico progettato nel WP2 del project work di **Algoritmi e Protocolli per la Sicurezza**.

La PoC simula un referendum binario con separazione tra Government Authority, Voting Server, Electoral Register / Bulletin Board e Scrutiny Authority distribuita simulata.

## Scelte implementative principali

Il prototipo non usa rete reale, app mobile, database persistenti o blockchain. Tutte le entità sono classi Python e tutti i registri sono strutture dati in memoria.

Le primitive usate sono coerenti con i laboratori del corso:

- RSA 2048 bit con OAEP e SHA-256 per la cifratura asimmetrica della scheda;
- RSA-PSS con SHA-256 per firme digitali;
- SHA-256 per commitment, digest e Merkle Tree;
- HMAC-SHA256 per il tag deterministico di lookup dei token spesi;
- Fernet per simulare un canale sicuro autenticato dopo verifica del certificato.

La Scrutiny Authority distribuita è simulata tramite autorizzazioni firmate da almeno `k` nodi certificati. Non viene implementata threshold decryption matematica: dopo il quorum `k-of-n`, la SA decifra con la chiave privata elettorale simulata.

## Setup

Richiede Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell
pip install -r requirements.txt
```

## Esecuzione demo

```bash
python main.py
```

La demo esegue una piccola elezione con 3 elettori idonei. Mostra:

- setup dell'elezione;
- certificazione delle entità;
- autenticazione e rilascio token;
- voto cifrato;
- registrazione su Bulletin Board append-only;
- ricevuta firmata dal Registro Elettorale;
- commit del token in `SpentTokensDB`;
- Merkle Tree e prova di inclusione;
- scrutinio finale;
- verifica universale simulata.

## Esecuzione test

```bash
python tests.py
```

I test coprono i casi minimi richiesti:

- elettore valido;
- elettore non idoneo;
- riuso del token;
- firma alterata;
- scheda/record alterato dopo la ricevuta;
- certificato revocato;
- replay della busta;
- coerenza dello scrutinio.

## Esecuzione benchmark

```bash
python benchmark.py
```

Il benchmark usa i valori definiti in `config.py`:

```python
BENCHMARK_VOTER_COUNTS = (10, 100, 500, 1000)
```

Se `1000` elettori risulta troppo lento sulla macchina locale, si può ridurre la tupla in `config.py`, ad esempio a `(10, 100, 500)`.

Il benchmark stampa una tabella riassuntiva in console ed esporta il CSV:

```text
benchmark_results.csv
```

## Interpretazione risultati

Le colonne principali del CSV sono:

- `key_generation_total_s`: tempo totale di generazione delle chiavi RSA usate nell'esperimento;
- `signature_avg_s`: tempo medio di firma;
- `signature_verification_avg_s`: tempo medio di verifica firma;
- `vote_encryption_avg_s`: tempo medio di cifratura della scheda;
- `vote_decryption_avg_s`: tempo medio di decifratura della scheda;
- `token_generation_avg_s`: tempo medio di generazione token;
- `token_verification_avg_s`: tempo medio di verifica token;
- `board_registration_avg_s`: tempo medio di registrazione su Bulletin Board;
- `merkle_build_total_s`: tempo totale di costruzione del Merkle Tree;
- `merkle_path_verification_avg_s`: tempo medio di verifica del Merkle path;
- `scrutiny_total_s`: tempo totale di scrutinio;
- `*_avg_bytes`: dimensione media dei messaggi principali serializzati in JSON canonico;
- `latency_per_vote_avg_s`: latenza media end-to-end per voto;
- `throughput_votes_per_second`: throughput approssimativo della fase di voto.

## Limiti della simulazione

Questa PoC mostra la correttezza del flusso e delle verifiche principali, ma non è un sistema elettorale reale.

Limiti principali:

- il canale sicuro è simulato con Fernet, non con TLS reale;
- certificati e CRL sono strutture dati firmate, non certificati X.509 reali;
- non esiste rete reale, quindi non vengono misurati ritardi di trasporto o attacchi DoS reali;
- non esiste database persistente, quindi atomicità e append-only sono simulate in memoria;
- la Scrutiny Authority distribuita è simulata con firme di autorizzazione `k-of-n`, non con threshold cryptography;
- la verificabilità universale controlla firme, Merkle root, numero record e coerenza numerica, ma non include prove pubbliche di corretta decifratura per ogni scheda;
- la coercizione non è risolta: la ricevuta non contiene la preferenza, ma screenshot, malware o osservazione fisica restano rischi esterni.

## File principali

- `main.py`: demo e dispatcher CLI;
- `config.py`: parametri globali;
- `crypto_utils.py`: primitive crittografiche e canale sicuro simulato;
- `models.py`: dataclass del protocollo;
- `government_authority.py`: autenticazione, idoneità, token, CA e CRL;
- `voting_client.py`: client elettore;
- `voting_server.py`: verifica token, anti-riuso e commit;
- `electoral_register.py`: Bulletin Board append-only, ricevute e Merkle Tree;
- `scrutiny_authority.py`: scrutinio e autorizzazioni distribuite simulate;
- `merkle.py`: Merkle Tree e proof verification;
- `verification.py`: verifica universale simulata;
- `benchmark.py`: benchmark e CSV;
- `tests.py`: test minimi.
