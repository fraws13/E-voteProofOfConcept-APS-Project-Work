"""Helper crittografici utilizzati dal PoC di e-voting WP4.

Il codice utilizza consapevolmente primitive molto vicine a quelle illustrate nelle slide di laboratorio:
- RSA per cifratura e firme asimmetriche,
- SHA-256 per funzioni di digest,
- HMAC per tag di autenticazione dei messaggi,
- Fernet per simulare un canale autenticato e cifrato (autenticazione simmetrica).
Tutto il codice è pensato per essere trasparente agli studenti nei suoi passaggi principali.
"""

from __future__ import annotations

# Moduli standard Python
import base64   # Per codifiche e decodifiche base64 (per trasportare chiavi e firme binarie come stringhe)
import hashlib  # Per funzioni di hash (SHA-256)
import hmac as py_hmac  # Per HMAC (autenticazione simmetrica)
import json     # Per serializzazioni e deserializzazioni JSON
import os       # Per funzioni di sistema come generazione di byte casuali
import time     # Per gestione dei timestamp
from typing import Any

# Moduli di terze parti per la crittografia
from cryptography.exceptions import InvalidSignature  # Eccezione sollevata in caso di verifica firma fallita
from cryptography.fernet import Fernet, InvalidToken  # Fernet per cifratura simmetrica “alla TLS”, InvalidToken per gestione errori Fernet
from cryptography.hazmat.primitives import hashes, serialization  # hash, serializzazione chiavi
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # padding RSA, generazione chiavi RSA

# Parametri per la generazione delle chiavi RSA prelevati dalla configurazione di sistema
from core.config import RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT

# --- TIPI DI CHIAVE PERSONALIZZATI --- #
# Alias di tipo per maggiore leggibilità: PrivateKey e PublicKey corrispondono agli oggetti delle librerie cryptography
PrivateKey = rsa.RSAPrivateKey
PublicKey = rsa.RSAPublicKey

# --- SERIALIZZAZIONE E CODIFICHE --- #
# Restituisce una rappresentazione JSON deterministica (chiavi ordinate, no spazi) utile per firme e hash.
def canonical_json(data: Any) -> str:
    """Restituisce una rappresentazione JSON deterministica per firme e hash (chiavi ordinate, formattazione compatta, UTF-8)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

# Converte un oggetto python in bytes tramite serializzazione JSON deterministica UTF-8.
def json_bytes(data: Any) -> bytes:
    return canonical_json(data).encode("utf-8")

# Codifica un array di byte come stringa base64. Utile per trasmettere dati binari (firme, chiavi, blob cifrati) come testo.
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

# Decodifica una stringa base64 e restituisce l'array di byte originale.
def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

# --- TEMPO E NONCE --- #
# Restituisce il timestamp UNIX corrente (secondi dal 1 gennaio 1970, intero).
def now_ts() -> int:
    return int(time.time())

# Genera un nonce casuale (stringa esadecimale, per evitare replay e attacchi di ripetizione).
def generate_nonce(num_bytes: int = 16) -> str:
    return os.urandom(num_bytes).hex()

# --- GESTIONE CHIAVI RSA --- #
# Genera una nuova coppia (privata, pubblica) di chiavi RSA. 
# Parametri di sicurezza (dimensione, esponente) presi dal file di config.
def generate_rsa_key_pair() -> tuple[PrivateKey, PublicKey]:
    # Crea una chiave privata RSA;
    # private_key.public_key() ricava la rispettiva chiave pubblica.
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()

# Converte una chiave pubblica RSA in formato testuale PEM (leggibile, utile per scambiare/certificare chiavi e salvarle su file).
def public_key_to_pem(public_key: PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

# Converte una chiave privata RSA in formato testuale PEM (utile per archiviazione sicura su file).
def private_key_to_pem(private_key: PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(), # Nessuna password, attenzione per sicurezza reale!
    ).decode("utf-8")

# Carica (deserializza) una chiave pubblica RSA da una stringa PEM.
def load_public_key(public_key_pem: str) -> PublicKey:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")  # Sicurezza: garantisce il tipo corretto
    return key

# Carica (deserializza) una chiave privata RSA da una stringa PEM.
def load_private_key(private_key_pem: str) -> PrivateKey:
    key = serialization.load_pem_private_key(public_key_pem_to_bytes(private_key_pem), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")  # Sicurezza: garantisce il tipo corretto
    return key

# Utility: converte una stringa PEM in array di byte (usato dalla funzione sopra).
def public_key_pem_to_bytes(private_key_pem: str) -> bytes:
    return private_key_pem.encode("utf-8")

# --- FIRME DIGITALI E VERIFICHE --- #
# Firma un messaggio (array di byte) usando la chiave privata RSA e il padding PSS SHA-256.
def sign_message(private_key: PrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),      # Mask generation function MGF1(SHA256)
            salt_length=padding.PSS.MAX_LENGTH,     # Sale casuale di lunghezza massima consentita
        ),
        hashes.SHA256(),
    )

# Verifica una firma RSA-PSS su un messaggio con la chiave pubblica corrispondente (ritorna True se valida, False se non valida).
def verify_signature(public_key: PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),   # Mask generation function MGF1(SHA256)
                salt_length=padding.PSS.MAX_LENGTH,  # Sale come da standard PSS
            ),
            hashes.SHA256(),
        )
        return True  # Se nessuna eccezione, la firma è valida
    except InvalidSignature:
        return False # Firma non valida

# --- CIFRATURA ASIMMETRICA (RSA) --- #
# Cifra un messaggio (array di byte) con la chiave pubblica RSA usando OAEP (SHA-256).
def rsa_encrypt(public_key: PublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # OAEP: Optimal Asymmetric Encryption Padding con SHA-256
            algorithm=hashes.SHA256(),
            label=None,                                   # Nessuna label supplementare
        ),
    )

# Decifra un messaggio cifrato con RSA OAEP, usando la chiave privata corrispondente.
def rsa_decrypt(private_key: PrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Come sopra, decodifica simmetrica
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# --- CIFRATURA IBRIDA (RSA + Fernet) --- #
def hybrid_encrypt(public_key: PublicKey, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Cifratura ibrida per messaggi troppo grandi per RSA puro.

    1. Si genera una chiave simmetrica casuale compatibile Fernet;
    2. Si cifra l'intero messaggio con Fernet (ossia con AES con autenticazione);
    3. Si cifra (wrappa) la chiave Fernet generata casualmente con la chiave pubblica RSA;
    4. Ritorna una tupla: (chiave_wrappata_RSA, messaggio_cifrato_Fernet).
    """
    fernet_key = Fernet.generate_key()                 # 1. Genera chiave simmetrica Fernet randomica
    ciphertext = Fernet(fernet_key).encrypt(plaintext) # 2. Cifra il plaintext con Fernet
    wrapped_key = rsa_encrypt(public_key, fernet_key)  # 3. Cifra la chiave simmetrica con RSA
    return wrapped_key, ciphertext                     # 4. Ritorna entrambe

# Decifra una coppia (key_wrapped, ciphertext): 1. decifra chiave simmetrica con RSA; 2. decifra il messaggio Fernet.
def hybrid_decrypt(private_key: PrivateKey, wrapped_key: bytes, ciphertext: bytes) -> bytes:
    fernet_key = rsa_decrypt(private_key, wrapped_key)
    return Fernet(fernet_key).decrypt(ciphertext)

# --- HASH E HMAC --- #
# Calcola la digest SHA-256 e la restituisce in esadecimale (stringa).
def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

# Calcola la digest SHA-256 come array di byte.
def sha256_bytes(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()

# Calcola HMAC-SHA256 dei dati, restituendo la rappresentazione esadecimale del tag.
def hmac_sha256_hex(key: bytes, data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return py_hmac.new(key, data, hashlib.sha256).hexdigest()

# --- SICUREZZA SUL TEMPO: CONTROLLO FRESCHEZZA --- #
# Verifica che un timestamp sia "fresco", cioè non più vecchio di window_seconds rispetto ad ora.
def is_fresh(timestamp: int, window_seconds: int) -> bool:
    return abs(now_ts() - timestamp) <= window_seconds

# --- SUPPORTO SERIALIZZAZIONE --- #
# Calcola il numero di byte della rappresentazione JSON deterministica di un oggetto (utile per statistiche/controlli).
def json_size(data: Any) -> int:
    return len(json_bytes(data))

# --- CLASSE DI CANALE AUTENTICATO SIMULATO (NO TLS REALE) --- #
class SecureChannel:
    """
    Canale autenticato e cifrato simulato basato su Fernet (AES + autenticazione).

    Attenzione: questa classe NON implementa davvero un TLS, ma simula solo il risultato atteso dal protocollo:
    - dopo la verifica dei certificati le due parti "posseggono" una chiave di sessione segreta
    - con questa cifrano e autenticano i messaggi scambiati mediante Fernet
    - la freschezza e la sicurezza sono modellate grazie ai token scaduti/validi Fernet con TTL.
    """

    def __init__(self) -> None:
        self.key = Fernet.generate_key()        # Genera chiave segreta simmetrica di sessione
        self._fernet = Fernet(self.key)         # Crea istanza Fernet per cifrature e autenticazione

    def protect(self, plaintext: bytes) -> bytes:
        # Cifra (e autentica) il messaggio usando la chiave Fernet della sessione.
        # Se l'attaccante modifica il messaggio cifrato, Fernet rileva la manipolazione.
        return self._fernet.encrypt(plaintext)
    
    # Decifra (e controlla autenticità e freschezza) il messaggio cifrato trasportato dal canale.
    # Se il token è scaduto o manomesso, Fernet solleva InvalidToken.
    def unprotect(self, token: bytes, ttl: int | None = None) -> bytes:
        try:
            return self._fernet.decrypt(token, ttl=ttl)
        except InvalidToken as exc:
            # Lancia eccezione specifica per segnalare che il messaggio sul canale non è valido o è scaduto
            raise ValueError("Secure channel message is invalid or expired") from exc
