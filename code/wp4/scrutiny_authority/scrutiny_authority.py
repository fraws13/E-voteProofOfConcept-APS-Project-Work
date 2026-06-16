"""Distributed Scrutiny Authority simulated with k-of-n signed authorizations."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Iterable

from crypto.certificates import verify_certificate
from core.config import ROLE_SA_NODE
from crypto.crypto_utils import (
    b64d,
    b64e,
    generate_rsa_key_pair,
    json_bytes,
    load_public_key,
    now_ts,
    public_key_to_pem,
    rsa_decrypt,
    sign_message,
    verify_signature,
)
from core.metrics import MetricsCollector
from core.models import BoardRecord, Certificate, CRL, ScrutinyAuthorization, TallyResult


@dataclass
class ScrutinyNode:
    node_id: str
    private_key: object
    public_key_pem: str
    certificate: Certificate
    metrics: MetricsCollector | None = None

    def authorize_scrutiny(self, election_id: str, root_final: str, record_count: int) -> ScrutinyAuthorization:
        payload = {
            "action": "AUTHORIZE_SCRUTINY",
            "election_id": election_id,
            "root_final": root_final,
            "record_count": record_count,
            "timestamp": now_ts(),
        }
        if self.metrics is None:
            signature = b64e(sign_message(self.private_key, json_bytes(payload)))
        else:
            with self.metrics.measure("sign"):
                signature = b64e(sign_message(self.private_key, json_bytes(payload)))
        return ScrutinyAuthorization(
            node_id=self.node_id,
            certificate=self.certificate,
            payload=payload,
            signature=signature,
        )


class ScrutinyAuthority:
    """Final tally authority.

    The PoC does not implement mathematical threshold decryption. The k-of-n
    part is simulated as a distributed authorization step: at least k certified
    SA nodes must sign the same scrutiny authorization. Only then the simulated
    SA decrypts ballots with the election private key.
    """

    def __init__(self, threshold: int, node_count: int, metrics: MetricsCollector | None = None) -> None:
        if threshold < 1 or threshold > node_count:
            raise ValueError("Invalid threshold parameters")
        self.threshold = threshold
        self.node_count = node_count
        self.metrics = metrics
        with self._measure("key_generation"):
            self.private_key, self.public_key = generate_rsa_key_pair()
        self.public_key_pem = public_key_to_pem(self.public_key)
        self.certificate: Certificate | None = None
        self.nodes: list[ScrutinyNode] = []

    def _measure(self, name: str):
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

    def set_certificate(self, certificate: Certificate) -> None:
        self.certificate = certificate

    def set_nodes(self, nodes: list[ScrutinyNode]) -> None:
        if len(nodes) != self.node_count:
            raise ValueError("Unexpected number of scrutiny nodes")
        self.nodes = nodes

    def collect_authorizations(self, election_id: str, root_final: str, record_count: int, how_many: int | None = None) -> list[ScrutinyAuthorization]:
        selected = self.nodes[: how_many or self.threshold]
        return [node.authorize_scrutiny(election_id, root_final, record_count) for node in selected]

    def _valid_authorizations(
        self,
        authorizations: Iterable[ScrutinyAuthorization],
        election_id: str,
        root_final: str,
        record_count: int,
        ga_public_key_pem: str,
        crl: CRL,
    ) -> list[ScrutinyAuthorization]:
        valid: list[ScrutinyAuthorization] = []
        seen_nodes: set[str] = set()

        for auth in authorizations:
            if auth.node_id in seen_nodes:
                continue
            if auth.payload.get("election_id") != election_id:
                continue
            if auth.payload.get("root_final") != root_final:
                continue
            if auth.payload.get("record_count") != record_count:
                continue
            if not verify_certificate(
                auth.certificate,
                expected_role=ROLE_SA_NODE,
                election_id=election_id,
                ga_public_key_pem=ga_public_key_pem,
                crl=crl,
                metrics=self.metrics,
            ):
                continue
            node_public_key = load_public_key(auth.certificate.public_key_pem)
            with self._measure("verify_signature"):
                if verify_signature(node_public_key, json_bytes(auth.payload), b64d(auth.signature)):
                    valid.append(auth)
                    seen_nodes.add(auth.node_id)
        return valid

    def scrutinize(
        self,
        records: list[BoardRecord],
        authorizations: list[ScrutinyAuthorization],
        election_id: str,
        root_final: str,
        ga_public_key_pem: str,
        crl: CRL,
    ) -> TallyResult:
        with self._measure("scrutiny"):
            valid_authorizations = self._valid_authorizations(
                authorizations=authorizations,
                election_id=election_id,
                root_final=root_final,
                record_count=len(records),
                ga_public_key_pem=ga_public_key_pem,
                crl=crl,
            )
            if len(valid_authorizations) < self.threshold:
                raise PermissionError("Not enough valid Scrutiny Authority node authorizations")

            count_yes = 0
            count_no = 0
            count_invalid = 0
            for record in records:
                try:
                    with self._measure("decrypt_vote"):
                        plaintext = rsa_decrypt(self.private_key, b64d(record.Mboard.encrypted_vote_b64))
                    vote_data = json.loads(plaintext.decode("utf-8"))
                    preference = vote_data.get("preference")
                    if preference == "YES":
                        count_yes += 1
                    elif preference == "NO":
                        count_no += 1
                    else:
                        count_invalid += 1
                except Exception:
                    count_invalid += 1

            unsigned = TallyResult(
                election_id=election_id,
                count_yes=count_yes,
                count_no=count_no,
                count_invalid=count_invalid,
                record_count=len(records),
                root_final=root_final,
                generated_at=now_ts(),
                authorizations=valid_authorizations,
            )
            with self._measure("sign"):
                signature = b64e(sign_message(self.private_key, json_bytes(unsigned.payload_dict())))
            return replace(unsigned, signature=signature)


def generate_scrutiny_node(node_id: str, certificate: Certificate | None = None, metrics: MetricsCollector | None = None) -> tuple[object, str]:
    if metrics is None:
        private_key, public_key = generate_rsa_key_pair()
    else:
        with metrics.measure("key_generation"):
            private_key, public_key = generate_rsa_key_pair()
    return private_key, public_key_to_pem(public_key)
