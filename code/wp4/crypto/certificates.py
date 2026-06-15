"""Certificate and CRL verification helpers."""

from __future__ import annotations

from crypto.crypto_utils import b64d, json_bytes, load_public_key, now_ts, verify_signature
from core.metrics import MetricsCollector
from core.models import CRL, Certificate


def verify_crl(crl: CRL, ga_public_key_pem: str, metrics: MetricsCollector | None = None) -> bool:
    #verifica la firma della CRL usando la chiave pubblica dell'Government Authority
    ga_public_key = load_public_key(ga_public_key_pem)
    if metrics is None:
        return verify_signature(ga_public_key, json_bytes(crl.payload_dict()), b64d(crl.signature))
    #verifica la firma della CRL usando la chiave pubblica dell'Government Authority
    with metrics.measure("verify_signature"):
        return verify_signature(ga_public_key, json_bytes(crl.payload_dict()), b64d(crl.signature))

#verifica la validità del certificato
def verify_certificate(
    certificate: Certificate,
    expected_role: str,
    election_id: str,
    ga_public_key_pem: str,
    crl: CRL,
    metrics: MetricsCollector | None = None,
) -> bool:
    #verifica che il ruolo del certificato sia quello atteso
    if certificate.role != expected_role:
        return False
    #verifica che l'id dell'elezione del certificato sia quello atteso
    if certificate.election_id != election_id:
        return False
    #verifica che il numero di serie del certificato non sia in lista dei certificati revocati
    if certificate.serial_number in set(crl.revoked_serials):
        return False
    current = now_ts()
    #verifica che il certificato sia stato emesso entro il tempo corrente e non sia scaduto
    if not (certificate.issued_at <= current <= certificate.valid_until):
        return False
    #verifica la validità della CRL
    if not verify_crl(crl, ga_public_key_pem, metrics):
        return False

    #verifica la firma del certificato usando la chiave pubblica dell'Government Authority
    ga_public_key = load_public_key(ga_public_key_pem)
    if metrics is None:
        return verify_signature(ga_public_key, json_bytes(certificate.payload_dict()), b64d(certificate.signature))
    #verifica la firma del certificato usando la chiave pubblica dell'Government Authority
    with metrics.measure("verify_signature"):
        return verify_signature(ga_public_key, json_bytes(certificate.payload_dict()), b64d(certificate.signature))
