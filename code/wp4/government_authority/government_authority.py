from __future__ import annotations

from datetime import datetime
from typing import Iterable
from crypto.crypto_utils import b64e, json_bytes, now_ts
from core.metrics import MetricsCollector
from core.models import AuthRequest, ElectionParameters, Certificate, VotingToken
from government_authority.identityProvider import IdentityProvider
from government_authority.eligibilityVerifier import EligibilityVerifier
from government_authority.certificateAuthority import CertificateAuthority
from government_authority.votingTokenIssuer import VotingTokenIssuer

class GovernmentAuthority:
    """
    Facade che orchestra i sottomoduli IP, EV, CA e VTI.
    Gestisce l'aggregazione di livello superiore (es. configurazione elezione).
    """

    '''inizializza il modulo GA'''
    def __init__(self, eligible_users: Iterable[str], metrics: MetricsCollector | None = None) -> None:
        self.metrics = metrics
        users_set = set(eligible_users)
        
        # Inizializzazione dei sottomoduli
        self.ip = IdentityProvider(users_set)
        self.ev = EligibilityVerifier(users_set)
        self.ca = CertificateAuthority(metrics)
        self.vti = VotingTokenIssuer(sign_callback=self.ca.sign_payload, metrics=metrics)

    # --- Deleghe ai Sottomoduli ---

    @property
    def public_key_pem(self) -> str:
        return self.ca.public_key_pem

    def issue_certificate(self, *args, **kwargs):
        return self.ca.issue_certificate(*args, **kwargs)

    def revoke_certificate(self, *args, **kwargs):
        return self.ca.revoke_certificate(*args, **kwargs)

    def current_crl(self, *args, **kwargs):
        return self.ca.current_crl(*args, **kwargs)

    def request_voting_token(self, user_id: str, auth_request: AuthRequest) -> VotingToken:
        if self.metrics is not None:
            self.metrics.add_size("AuthRequest", auth_request.to_dict())

        # 1. Verifica IP
        if not self.ip.authenticate_internal(user_id):
            raise PermissionError("Authentication failed or unknown user")
        
        # 2. Verifica EV
        if not self.ev.is_eligible(user_id):
            raise PermissionError("User is not eligible")

        # 3. Emissione VTI
        return self.vti.request_voting_token(user_id, auth_request)

    # --- Metodi di Aggregazione ---

    def create_election_parameters(self, election_id: str, election_type: str, options: tuple[str, ...], opens_at: datetime, closes_at: datetime, cert_vs: Certificate, cert_er: Certificate, certs_sa: Certificate, scrutiny_nodes: int, scrutiny_threshold: int, scrutiny_public_key_pem: str, timestamp: datetime) -> ElectionParameters:
        """La creazione dei parametri elettorali è una responsabilità di orchestrazione (GA)."""
        unsigned = ElectionParameters(
            election_id=election_id,
            election_type=election_type,
            options=options,
            # i datetime non sono serializzabili in JSON: si convertono in timestamp interi per coerenza con la firma
            opens_at=int(opens_at.timestamp()),
            closes_at=int(closes_at.timestamp()),
            ga_public_key_pem=self.ca.public_key_pem,
            scrutiny_public_key_pem=scrutiny_public_key_pem,
            scrutiny_threshold=scrutiny_threshold,
            scrutiny_nodes=scrutiny_nodes,
            cert_vs_serial=cert_vs.serial_number,
            cert_er_serial=cert_er.serial_number,
            cert_sa_serial=certs_sa.serial_number,
            issued_at=int(timestamp.timestamp()),
        )
        # Utilizza la CA per firmare i parametri governativi
        signature = b64e(self.ca.sign_payload(json_bytes(unsigned.payload_dict())))
        return ElectionParameters(**unsigned.payload_dict(), signature=signature)

    def describe_internal_state(self) -> dict[str, object]:
        return {
            "eligible_users": len(self.ev._eligible_users),
            "issued_tokens": len(self.vti.issued_tokens_db),
            "revoked_certificates": len(self.ca.revoked_cert_serials),
        }