"""Data models for the WP4 e-voting Proof of Concept."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Certificate:
    subject: str
    role: str
    election_id: str
    public_key_pem: str
    serial_number: str
    issued_at: int
    valid_until: int
    issuer: str = "GA"
    election_type: str = "REFERENDUM"
    organization_info: str = ""
    valid_from: int = 0
    valid_to: int = 0
    nonce: str = ""
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "role": self.role,
            "election_id": self.election_id,
            "public_key_pem": self.public_key_pem,
            "serial_number": self.serial_number,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "issuer": self.issuer,
            "election_type": self.election_type,
            "organization_info": self.organization_info,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class CRL:
    election_id: str
    revoked_serials: list[str]
    issued_at: int
    issuer: str = "GA"
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "revoked_serials": sorted(self.revoked_serials),
            "issued_at": self.issued_at,
            "issuer": self.issuer,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class ElectionParameters:
    election_id: str
    election_type: str
    options: tuple[str, ...]
    opens_at: int
    closes_at: int
    ga_public_key_pem: str
    scrutiny_public_key_pem: str
    scrutiny_threshold: int
    scrutiny_nodes: int
    cert_vs_serial: str
    cert_er_serial: str
    cert_sa_serial: str
    issued_at: int
    version: int = 1
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "election_type": self.election_type,
            "options": list(self.options),
            "opens_at": self.opens_at,
            "closes_at": self.closes_at,
            "ga_public_key_pem": self.ga_public_key_pem,
            "scrutiny_public_key_pem": self.scrutiny_public_key_pem,
            "scrutiny_threshold": self.scrutiny_threshold,
            "scrutiny_nodes": self.scrutiny_nodes,
            "cert_vs_serial": self.cert_vs_serial,
            "cert_er_serial": self.cert_er_serial,
            "cert_sa_serial": self.cert_sa_serial,
            "issued_at": self.issued_at,
            "version": self.version,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class AuthRequest:
    election_id: str
    voter_public_key_pem: str
    nonce: str
    timestamp: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "voter_public_key_pem": self.voter_public_key_pem,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class Permit:
    election_id: str
    serial_number: str
    voter_public_key_pem: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "serial_number": self.serial_number,
            "voter_public_key_pem": self.voter_public_key_pem,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class VotingToken:
    permit: Permit
    signature: str

    def payload_dict(self) -> dict[str, Any]:
        return self.permit.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit": self.permit.to_dict(),
            "signature": self.signature,
        }

@dataclass(frozen=True)
class EncToken:
    encrypted_key_b64: str
    encrypted_token_b64: str

    def to_dict(self) -> dict:
        return {
            "encrypted_key_b64": self.encrypted_key_b64,
            "encrypted_token_b64": self.encrypted_token_b64,
        }


@dataclass(frozen=True)
class Ballot:
    election_id: str
    token: VotingToken
    voter_public_key_pem: str
    encrypted_vote_b64: str
    ballot_commit: str
    nonce_ballot: str
    timestamp: int
    signature: str = ""

    def unsigned_payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "token": self.token.to_dict(),
            "voter_public_key_pem": self.voter_public_key_pem,
            "encrypted_vote_b64": self.encrypted_vote_b64,
            "ballot_commit": self.ballot_commit,
            "nonce_ballot": self.nonce_ballot,
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.unsigned_payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class Mboard:
    """Messaggio firmato dal Voting Server e inoltrato all'Electoral Register."""

    election_id: str
    encrypted_vote_b64: str
    timestamp: int
    commit: str
    nonce_ballot: str
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "encrypted_vote_b64": self.encrypted_vote_b64,
            "timestamp": self.timestamp,
            "commit": self.commit,
            "nonce_ballot": self.nonce_ballot,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class BoardRecord:
    index: int
    Mboard: Mboard
    timestamp_er: int
    previous_record_hash: str
    record_hash: str

    def payload_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "Mboard": self.Mboard.to_dict(),
            "timestamp_er": self.timestamp_er,
            "previous_record_hash": self.previous_record_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["record_hash"] = self.record_hash
        return data


@dataclass(frozen=True)
class Receipt:
    election_id: str
    leaf_hash: str
    ballot_commit: str
    encrypted_vote_hash: str
    timestamp: int
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "leaf_hash": self.leaf_hash,
            "ballot_commit": self.ballot_commit,
            "encrypted_vote_hash": self.encrypted_vote_hash,
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature"] = self.signature
        return data


@dataclass(frozen=True)
class MerkleProof:
    record_index: int
    root: str
    path: list[tuple[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_index": self.record_index,
            "root": self.root,
            "path": [{"position": pos, "hash": h} for pos, h in self.path],
        }


@dataclass
class SpentTokenEntry:
    lookup_tag: str
    status: str
    created_at: int
    record_index: int | None = None
    committed_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lookup_tag": self.lookup_tag,
            "status": self.status,
            "created_at": self.created_at,
            "record_index": self.record_index,
            "committed_at": self.committed_at,
        }


@dataclass(frozen=True)
class ScrutinyAuthorization:
    node_id: str
    certificate: Certificate
    payload: dict[str, Any]
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "certificate": self.certificate.to_dict(),
            "payload": self.payload,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class TallyResult:
    election_id: str
    count_yes: int
    count_no: int
    count_invalid: int
    record_count: int
    root_final: str
    generated_at: int
    authorizations: list[ScrutinyAuthorization] = field(default_factory=list)
    signature: str = ""

    def payload_dict(self) -> dict[str, Any]:
        return {
            "election_id": self.election_id,
            "count_yes": self.count_yes,
            "count_no": self.count_no,
            "count_invalid": self.count_invalid,
            "record_count": self.record_count,
            "root_final": self.root_final,
            "generated_at": self.generated_at,
            "authorization_node_ids": sorted(a.node_id for a in self.authorizations),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["authorizations"] = [a.to_dict() for a in self.authorizations]
        data["signature"] = self.signature
        return data
