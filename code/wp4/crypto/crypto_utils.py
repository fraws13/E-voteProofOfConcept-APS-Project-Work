"""Cryptographic helpers used by the WP4 e-voting PoC.

The code intentionally stays close to the primitives used in the laboratory
slides: RSA for asymmetric encryption/signatures, SHA-256 for digests, HMAC for
message authentication tags, and Fernet for the simulated authenticated secure
channel.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as py_hmac
import json
import os
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from core.config import RSA_KEY_SIZE, RSA_PUBLIC_EXPONENT

#definizione dei tipi di chiave RSA
PrivateKey = rsa.RSAPrivateKey
PublicKey = rsa.RSAPublicKey

#funzione utilizzata per convertire un oggetto in una stringa JSON deterministica
def canonical_json(data: Any) -> str:
    """Return a deterministic JSON representation for signing and hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

#funzione utilizzata per convertire una stringa JSON in un array di byte
def json_bytes(data: Any) -> bytes:
    return canonical_json(data).encode("utf-8")

#funzione utilizzata per convertire un array di byte in una stringa base64
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

#funzione utilizzata per convertire una stringa base64 in un array di byte
def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

#funzione utilizzata per ottenere il timestamp corrente
def now_ts() -> int:
    return int(time.time())

#funzione utilizzata per generare un nonce casuale di 16 byte
def generate_nonce(num_bytes: int = 16) -> str:
    return os.urandom(num_bytes).hex()

#funzione utilizzata per generare una coppia di chiavi RSA
def generate_rsa_key_pair() -> tuple[PrivateKey, PublicKey]:
    #genera una chiave privata RSA, la chiave pubblica è derivata dalla chiave privata
    private_key = rsa.generate_private_key(

        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()

#funzione utilizzata per convertire una chiave pubblica RSA in una stringa PEM
#in questo modo è possibile salvare la chiave pubblica in un file e certificati
def public_key_to_pem(public_key: PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

#funzione utilizzata per convertire una chiave privata RSA in una stringa PEM
def private_key_to_pem(private_key: PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def load_public_key(public_key_pem: str) -> PublicKey:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return key


def load_private_key(private_key_pem: str) -> PrivateKey:
    key = serialization.load_pem_private_key(public_key_pem_to_bytes(private_key_pem), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


def public_key_pem_to_bytes(private_key_pem: str) -> bytes:
    return private_key_pem.encode("utf-8")


def sign_message(private_key: PrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key: PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(public_key: PublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: PrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def hybrid_encrypt(public_key: PublicKey, plaintext: bytes) -> tuple[bytes, bytes]:
    """Cifratura ibrida per payload più grandi del limite RSA-OAEP.

    Genera una chiave Fernet (simmetrica), cifra il payload con essa e
    "incarta" (wrap) la chiave Fernet con RSA. Restituisce (chiave_wrappata, ciphertext).
    """
    fernet_key = Fernet.generate_key()
    ciphertext = Fernet(fernet_key).encrypt(plaintext)
    wrapped_key = rsa_encrypt(public_key, fernet_key)
    return wrapped_key, ciphertext


def hybrid_decrypt(private_key: PrivateKey, wrapped_key: bytes, ciphertext: bytes) -> bytes:
    fernet_key = rsa_decrypt(private_key, wrapped_key)
    return Fernet(fernet_key).decrypt(ciphertext)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def hmac_sha256_hex(key: bytes, data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return py_hmac.new(key, data, hashlib.sha256).hexdigest()


def is_fresh(timestamp: int, window_seconds: int) -> bool:
    return abs(now_ts() - timestamp) <= window_seconds


def json_size(data: Any) -> int:
    return len(json_bytes(data))

class SecureChannel:
    """Simulated authenticated secure channel based on Fernet.

    This is not a real TLS implementation. It models the outcome required by
    the protocol: after certificate verification, the parties share an
    authenticated encrypted channel with freshness support from Fernet tokens.
    """

    def __init__(self) -> None:
        self.key = Fernet.generate_key()
        self._fernet = Fernet(self.key)

    def protect(self, plaintext: bytes) -> bytes:
        #cifro il voto con la chiave sessione del canale di comunicazione
        return self._fernet.encrypt(plaintext)
    
    #funzione utilizzata per decifrare il voto con la chiave sessione del canale di comunicazione
    def unprotect(self, token: bytes, ttl: int | None = None) -> bytes:
        try:
            return self._fernet.decrypt(token, ttl=ttl)
        except InvalidToken as exc:
            raise ValueError("Secure channel message is invalid or expired") from exc
