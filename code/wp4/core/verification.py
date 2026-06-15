"""Universal verification helpers for the simulated public data."""

from __future__ import annotations

from crypto.certificates import verify_certificate
from core.config import ROLE_SA
from crypto.crypto_utils import b64d, json_bytes, load_public_key, verify_signature
from electoral_register.electoral_register import ElectoralRegister
from core.metrics import MetricsCollector
from core.models import CRL, Certificate, TallyResult


def verify_tally_signature(result: TallyResult, cert_sa: Certificate, crl: CRL, ga_public_key_pem: str, metrics: MetricsCollector | None = None) -> bool:
    if not verify_certificate(cert_sa, ROLE_SA, result.election_id, ga_public_key_pem, crl, metrics):
        return False
    sa_public_key = load_public_key(cert_sa.public_key_pem)
    if metrics is None:
        return verify_signature(sa_public_key, json_bytes(result.payload_dict()), b64d(result.signature))
    with metrics.measure("verify_signature"):
        return verify_signature(sa_public_key, json_bytes(result.payload_dict()), b64d(result.signature))


def verify_universal_result(
    register: ElectoralRegister,
    result: TallyResult,
    cert_sa: Certificate,
    crl: CRL,
    ga_public_key_pem: str,
    metrics: MetricsCollector | None = None,
) -> bool:
    if result.record_count != len(register.records):
        return False
    if result.count_yes + result.count_no + result.count_invalid != result.record_count:
        return False
    if register.root_final is None:
        return False
    if register.recompute_root() != register.root_final:
        return False
    if result.root_final != register.root_final:
        return False
    return verify_tally_signature(result, cert_sa, crl, ga_public_key_pem, metrics)
