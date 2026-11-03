from __future__ import annotations

import threading
import uuid
from typing import Callable

from core.config import TOKEN_VALIDITY_SECONDS
from crypto.crypto_utils import (
    b64e,
    generate_nonce,
    json_bytes,
    now_ts,
    load_public_key,
    hybrid_encrypt,
)
from core.metrics import MetricsCollector
from core.models import AuthRequest, Permit, VotingToken, EncToken


class VotingTokenIssuer:
    """Modulo VTI (Voting Token Issuer): Emissione e tracciamento dei token di voto."""

    def __init__(
        self,
        sign_callback: Callable[[bytes], bytes],
        metrics: MetricsCollector | None = None,
    ) -> None:
        self.metrics = metrics
        self.issued_tokens_db: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock() #lock per la sincronizzazione degli accessi al database dei token emessi
        self._sign = sign_callback  # Iniezione della dipendenza per la firma

    def _measure(self, name: str):
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

    def generate_token(self, auth_request: AuthRequest) -> tuple[EncToken, str]:
        """Genera, firma e cifra il token per la chiave pubblica dell'elettore.

        Restituisce l'EncToken (token cifrato in modo ibrido) e il serial_number
        in chiaro, necessario alla GA per il tracciamento dei token emessi.
        """
        with self._measure("token_generation"):
            ts = now_ts()
            voter_public_key = load_public_key(auth_request.voter_public_key_pem)
            permit = Permit(
                election_id=auth_request.election_id,
                serial_number=f"TOK-{uuid.uuid4().hex}-{generate_nonce(4)}",
                voter_public_key_pem=auth_request.voter_public_key_pem,
                issued_at=ts,
                expires_at=ts + TOKEN_VALIDITY_SECONDS,
            )

            # Utilizza il servizio di firma iniettato (es. della CA)
            signature = b64e(self._sign(json_bytes(permit.to_dict())))
            token = VotingToken(permit=permit, signature=signature)
            # cifratura ibrida: il token è troppo grande per RSA diretto
            wrapped_key, ciphertext = hybrid_encrypt(
                voter_public_key, json_bytes(token.to_dict())
            )

        if self.metrics is not None:
            self.metrics.add_size("Token", token.to_dict())

        enc_token = EncToken(
            encrypted_key_b64=b64e(wrapped_key),
            encrypted_token_b64=b64e(ciphertext),
        )
        return enc_token, permit.serial_number

    def request_voting_token(self, user_id: str, auth_request: AuthRequest) -> EncToken:
        # verifica che il token non sia già stato emesso per questo utente e questa elezione
        issued_key = (user_id, auth_request.election_id)
        with self._lock:
            if (
                issued_key in self.issued_tokens_db
            ):  # se il token è già stato emesso, solleva un errore
                raise PermissionError(
                    "A token has already been issued for this user and election"
                )

            enc_token, serial_number = self.generate_token(auth_request)  # genera un token di voto
            self.issued_tokens_db[issued_key] = (
                serial_number
            )  # memorizza il serial del token nel database dei token emessi
            return enc_token  # restituisce il token cifrato
