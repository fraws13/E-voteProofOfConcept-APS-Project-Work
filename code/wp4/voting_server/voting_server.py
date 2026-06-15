"""Voting Server: token verification, anti-reuse state and forwarding to ER."""

from __future__ import annotations

import json
import os

from crypto.certificates import verify_certificate
from core.config import FRESHNESS_WINDOW_SECONDS, ROLE_ER
from crypto.crypto_utils import (
    SecureChannel,
    b64d,
    b64e,
    hmac_sha256_hex,
    is_fresh,
    json_bytes,
    load_public_key,
    now_ts,
    sha256_bytes,
    sha256_hex,
    sign_message,
    verify_signature,
)
from electoral_register.electoral_register import ElectoralRegister
from core.metrics import MetricsCollector
from core.models import Ballot, Certificate, CRL, Mboard, Permit, SpentTokenEntry, VotingToken


# classe utilizzata per creare un voting server che permette di ricevere e verificare le buste di voto
class VotingServer:
    def __init__(
        self,
        vs_id: str,
        private_key,
        public_key_pem: str,
        metrics: MetricsCollector | None = None,
    ) -> None:
        self.vs_id = vs_id  # id del voting server
        self.private_key = private_key  # chiave privata del voting server
        self.public_key_pem = public_key_pem  # chiave pubblica del voting server
        self.metrics = metrics  # metriche del voting server
        self.k_master_server = os.urandom(32)  # chiave master del voting server
        self.spent_tokens_db: dict[str, SpentTokenEntry] = (
            {}
        )  # database dei token spesi
        self.seen_ballot_nonces: set[str] = set()  # set dei nonce dei voti già visti

    # funzione utilizzata per misurare le metriche del voting server
    def _measure(self, name: str):
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

    #
    def derive_spent_key(self, election_id: str) -> bytes:
        # K_Spent^Election = H(K_Master_Server || ID_Election)
        return sha256_bytes(self.k_master_server + election_id.encode("utf-8"))
        # in questo modo evito di usare k_master_server in chiaro

    #
    def lookup_tag_for_token(self, token: VotingToken) -> str:
        # LookupTag_Token = HMAC_KSpent(SerialNumber_Token)
        k_spent = self.derive_spent_key(token.permit.election_id)
        return hmac_sha256_hex(k_spent, token.permit.serial_number)

    # verifica la validità del token di voto
    def verify_token(
        self,
        token: VotingToken,
        ga_public_key_pem: str,
        expected_voter_public_key_pem: str,
    ) -> bool:
        with self._measure("token_verification"):
            # il token è firmato dalla GA, non dall'elettore: qui verifico solo che il token
            # sia legato (bound) all'elettore che firma la busta
            if token.permit.voter_public_key_pem != expected_voter_public_key_pem:
                raise ValueError("Token is not bound to this voter")
        # verifico che il token sia ancora valido
        if not (token.permit.issued_at <= now_ts() <= token.permit.expires_at):
            return False
        # verifico la firma del token usando la chiave pubblica dell'Government Authority
        ga_public_key = load_public_key(ga_public_key_pem)
        with self._measure("verify_signature"):
            return verify_signature(
                ga_public_key, json_bytes(token.permit.to_dict()), b64d(token.signature)
            )

    # funzione utilizzata per ricevere la busta di voto protetta, gestisce il livello di comunicaizione sicura
    def receive_secure_ballot(
        self,
        protected_envelope: bytes,
        channel: SecureChannel,
        electoral_register: ElectoralRegister,
        cert_er: Certificate,
        crl: CRL,
        ga_public_key_pem: str,
    ):
        # decifro la busta di voto protetta con il canale di comunicazione
        plaintext = channel.unprotect(protected_envelope, ttl=FRESHNESS_WINDOW_SECONDS)
        # converto il plaintext in un oggetto Ballot
        envelope = _ballot_envelope_from_dict(json.loads(plaintext.decode("utf-8")))
        # ricevo la busta di voto
        return self.receive_ballot(
            envelope, electoral_register, cert_er, crl, ga_public_key_pem
        )

    # gestisce il protocollo di ricezione della busta di voto e la verifica della busta di voto
    def receive_ballot(
        self,
        envelope: Ballot,
        electoral_register: ElectoralRegister,
        cert_er: Certificate,
        crl: CRL,
        ga_public_key_pem: str,
    ):
        # 1. Cheap syntactic/freshness checks first.
        if not is_fresh(envelope.timestamp, FRESHNESS_WINDOW_SECONDS):
            # controlla che il timestamp è troppo vecchio o troppo avanti
            raise ValueError("Ballot envelope is not fresh")
        if envelope.nonce_ballot in self.seen_ballot_nonces:
            # controlla che il nonce del voto non sia già stato visto
            raise ValueError("Replay detected: ballot nonce already seen")

        # 2. Verifica il certificato dell'Electoral Register prima di fare qualsiasi altra cosa.
        # controlla se il certificato dell'Electoral Register è valido e se non è presente nella CRL
        if not verify_certificate(
            cert_er,
            expected_role=ROLE_ER,
            election_id=envelope.election_id,
            ga_public_key_pem=ga_public_key_pem,
            crl=crl,
            metrics=self.metrics,
        ):
            raise ValueError("Electoral Register certificate rejected")

        # 3. Verifica il token di voto: firma GA, validità temporale e binding all'elettore.
        if not self.verify_token(envelope.token, ga_public_key_pem, envelope.voter_public_key_pem):
            raise ValueError("Invalid voting token")

        # 4 calcolo il lookup tag per il token di voto
        lookup_tag = self.lookup_tag_for_token(envelope.token)
        if lookup_tag in self.spent_tokens_db:
            # controlla se il token è già stato speso
            raise ValueError(
                f"Token reuse detected: state={self.spent_tokens_db[lookup_tag].status}"
            )

        # 4. commitment dichiarato nella busta corrisponda davvero al voto cifrato.
        expected_commit = sha256_hex(
            json_bytes(
                {
                    "election_id": envelope.election_id,
                    "encrypted_vote_b64": envelope.encrypted_vote_b64,
                    "nonce_ballot": envelope.nonce_ballot,
                }
            )
        )
        if expected_commit != envelope.ballot_commit:
            raise ValueError("Ballot commitment does not match encrypted ballot")

        #verifica la firma dell'elettore sulla busta di voto
        voter_public_key = load_public_key(envelope.voter_public_key_pem)
        with self._measure("verify_signature"):
            if not verify_signature(
                voter_public_key,
                json_bytes(envelope.unsigned_payload_dict()),
                b64d(envelope.signature),
            ):
                raise ValueError("Invalid voter signature on ballot envelope")

        # 5. Inserisci il token come "pending" solo dopo che tutti i controlli di accettazione sono passati.
        self.spent_tokens_db[lookup_tag] = SpentTokenEntry(
            lookup_tag=lookup_tag,
            status="pending",
            created_at=now_ts(),
        )
        #aggiungo il nonce del voto al set dei nonce già visti
        self.seen_ballot_nonces.add(envelope.nonce_ballot)

        #costruisco e firmo il messaggio Mboard (VS -> ER) con la chiave privata del voting server
        timestamp = now_ts()
        unsigned_mboard = Mboard(
            election_id=envelope.election_id,
            encrypted_vote_b64=envelope.encrypted_vote_b64,
            nonce_ballot=envelope.nonce_ballot,
            timestamp=timestamp,
            commit=envelope.ballot_commit,
        )
        signature = b64e(sign_message(self.private_key, json_bytes(unsigned_mboard.payload_dict())))
        mboard = Mboard(**unsigned_mboard.payload_dict(), signature=signature)
        # 6. Invia l'Mboard: l'ER verifica la firma del VS e produce la receipt
        receipt = electoral_register.append_record(envelope, mboard, self.public_key_pem)
        #verifico la firma della ricevuta dell'Electoral Register
        er_public_key = load_public_key(cert_er.public_key_pem)
        with self._measure("verify_signature"):
            if not verify_signature(
                er_public_key,
                json_bytes(receipt.payload_dict()),
                b64d(receipt.signature),
            ):
                raise ValueError("Invalid ER receipt signature")

        #aggiorno lo stato del token come "committed"
        entry = self.spent_tokens_db[lookup_tag]
        entry.status = "committed"
        entry.committed_at = now_ts()
        return receipt


def _ballot_envelope_from_dict(data: dict) -> Ballot:
    permit_data = data["token"]["permit"]
    permit = Permit(
        election_id=permit_data["election_id"],
        serial_number=permit_data["serial_number"],
        voter_public_key_pem=permit_data["voter_public_key_pem"],
        issued_at=permit_data["issued_at"],
        expires_at=permit_data["expires_at"],
    )
    token = VotingToken(permit=permit, signature=data["token"]["signature"])
    return Ballot(
        election_id=data["election_id"],
        token=token,
        voter_public_key_pem=data["voter_public_key_pem"],
        encrypted_vote_b64=data["encrypted_vote_b64"],
        ballot_commit=data["ballot_commit"],
        nonce_ballot=data["nonce_ballot"],
        timestamp=data["timestamp"],
        signature=data["signature"],
    )
