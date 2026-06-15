from __future__ import annotations
from core.config import (
    CERT_VALIDITY_SECONDS,
    ROLE_ER,
    ROLE_GA,
    ROLE_SA,
    ROLE_SA_NODE,
    ROLE_VS,
    ELECTION_TYPE,
)
from crypto.crypto_utils import (
    b64e,
    generate_rsa_key_pair,
    json_bytes,
    now_ts,
    public_key_to_pem,
    sign_message,
)
from core.metrics import MetricsCollector
from core.models import Certificate, CRL
from datetime import datetime

class CertificateAuthority:
    """Modulo CA (Certificate Authority): Gestione chiavi, certificati e CRL."""

    '''inizializza il modulo CA'''
    def __init__(self, metrics: MetricsCollector | None = None) -> None:
        self.metrics = metrics
        #crea un contatore per i certificati
        self._cert_counter = 1000
        #crea un set dei certificati che sono stati revocati
        self.revoked_cert_serials: set[str] = set()
        #genera la chiave privata e pubblica per il modulo CA
        with self._measure("key_generation"):
            self.private_key, self.public_key = generate_rsa_key_pair()
        #converte la chiave pubblica in formato PEM, così da poterla inserire nel certificato e far si che possa essere utilizzata
        #da tutti per verificare la firma
        self.public_key_pem = public_key_to_pem(self.public_key)

    #misura il tempo di esecuzione di una funzione
    def _measure(self, name: str):
        #se non ci sono metriche, restituisce un contextlib.nullcontext()
        if self.metrics is None:
            from contextlib import nullcontext
            return nullcontext()
        return self.metrics.measure(name)

    #genera il numero di serie del certificato
    def _next_cert_serial(self) -> str:
        #incrementa il contatore dei certificati
        self._cert_counter += 1
        return f"CERT-{self._cert_counter}"


    #firma il payload
    def sign_payload(self, payload: bytes) -> bytes:
        """Fornisce un servizio di firma centralizzato per i payload."""
        #misura il tempo di esecuzione della firma
        with self._measure("sign"):
            #firma il payload
            return sign_message(self.private_key, payload)

    #emette il certificato
    def issue_certificate(self, subject: str, role: str, election_id: str, public_key_pem: str, organization_info: str, valid_from: datetime, valid_to: datetime, nonce: str) -> Certificate:
        #verifica se il ruolo del certificato è supportato
        if role not in {ROLE_GA, ROLE_VS, ROLE_ER, ROLE_SA, ROLE_SA_NODE}:
            raise ValueError(f"Unsupported certificate role: {role}")

        #ottiene la data di emissione del certificato
        issued_at = now_ts()
        #crea il certificato non firmato
        unsigned = Certificate(
            subject=subject,
            role=role,
            election_id=election_id,
            election_type=ELECTION_TYPE,
            public_key_pem=public_key_pem,
            organization_info=organization_info,
            # i datetime non sono serializzabili in JSON: si convertono in timestamp interi per coerenza con il resto del modello e con la firma
            valid_from=int(valid_from.timestamp()),
            valid_to=int(valid_to.timestamp()),
            nonce=nonce,
            serial_number=self._next_cert_serial(),
            issued_at=issued_at,
            valid_until=issued_at + CERT_VALIDITY_SECONDS,
        )
        #firma il certificato
        signature = b64e(self.sign_payload(json_bytes(unsigned.payload_dict())))
        return Certificate(**unsigned.payload_dict(), signature=signature)

    #revocca il certificato
    def revoke_certificate(self, certificate: Certificate) -> None:
        #aggiunge il numero di serie del certificato alla lista dei certificati revocati
        self.revoked_cert_serials.add(certificate.serial_number)

    #genera il CRL
    def current_crl(self, election_id: str) -> CRL:
        #crea il CRL non firmato
        unsigned = CRL(
            election_id=election_id,
            revoked_serials=sorted(self.revoked_cert_serials),
            issued_at=now_ts(),
        )
        #firma il CRL
        signature = b64e(self.sign_payload(json_bytes(unsigned.payload_dict())))
        return CRL(**unsigned.payload_dict(), signature=signature)