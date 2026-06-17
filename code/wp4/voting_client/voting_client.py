"""Voting Client simulated in memory."""

from __future__ import annotations

from dataclasses import replace
import json
from core.config import FRESHNESS_WINDOW_SECONDS, ROLE_ER, ROLE_VS
from crypto.certificates import verify_certificate
from crypto.crypto_utils import (
    SecureChannel,
    b64d,
    b64e,
    canonical_json,
    generate_nonce,
    generate_rsa_key_pair,
    json_bytes,
    load_public_key,
    now_ts,
    public_key_to_pem,
    rsa_encrypt,
    sha256_hex,
    sign_message,
    verify_signature,
    hybrid_decrypt,
)
from core.metrics import MetricsCollector
from core.models import AuthRequest, Ballot, Certificate, CRL, ElectionParameters, MerkleProof, Permit, Receipt, VotingToken, EncToken
import crypto.merkle as merkle

#classe utilizzata per creare un voting client che permette all'utente di votare
class VotingClient:
    def __init__(self, election_params: ElectionParameters, metrics: MetricsCollector | None = None) -> None:
        self.params = election_params #parametri dell'elezione
        self.metrics = metrics #metriche dell'elezione
        with self._measure("key_generation"): #genera una chiave privata e pubblica RSA per l'elettore
            self.private_key, self.public_key = generate_rsa_key_pair()
        self.public_key_pem = public_key_to_pem(self.public_key) #chiave pubblica RSA convertita in PEM
        self.token: VotingToken | None = None #token di voto ricevuto dall'Government Authority
        self.ballot: Ballot | None = None #ultimo busta di voto creato
        self.last_receipt: Receipt | None = None #ultima ricevuta di voto
        self.ballot_commit: str | None = None #commit del voto
        
    def _measure(self, name: str):
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

    def build_auth_request(self) -> AuthRequest:
        #crea un oggetto AuthRequest che contiene l'id dell'elezione, la chiave pubblica RSA dell'elettore nonce e timestamp
        req = AuthRequest(
            election_id=self.params.election_id,
            voter_public_key_pem=self.public_key_pem,
            nonce=generate_nonce(),
            timestamp=now_ts(),
        )
        #misura  la dimensione dell'oggetto AuthRequest nel benchmark
        if self.metrics is not None:
            self.metrics.add_size("AuthRequest", req.to_dict())
        #restituisce l'oggetto AuthRequest
        return req

    #funzione utilizzata per memorizzare e verificare il token di voto ricevuto dall'Government Authority
    def store_and_verify_token(self, enc_token: EncToken) -> None:
        #decifra il token (ibrido: chiave Fernet wrappata con RSA + token cifrato con Fernet)
        decrypted_token = hybrid_decrypt(
            self.private_key,
            b64d(enc_token.encrypted_key_b64),
            b64d(enc_token.encrypted_token_b64),
        )
        #ricostruisce l'oggetto VotingToken dal JSON decifrato
        data = json.loads(decrypted_token)
        token = VotingToken(permit=Permit(**data["permit"]), signature=data["signature"])
        #verifica che il token sia per l'elezione corrente
        if token.permit.election_id != self.params.election_id:
            raise ValueError("Token is for a different election")
        #verifica che il token sia legato alla chiave pubblica dell'elettore
        if token.permit.voter_public_key_pem != self.public_key_pem:
            raise ValueError("Token is not bound to this client's public key")
        #verifica la firma del token usando la chiave pubblica dell'Government Authority
        ga_public_key = load_public_key(self.params.ga_public_key_pem)
        with self._measure("verify_signature"):
            ok = verify_signature(ga_public_key, json_bytes(token.permit.to_dict()), b64d(token.signature))
        if not ok: #se la firma non è valida, solleva un errore
            raise ValueError("Invalid GA signature on token")
        self.token = token
        if self.metrics is not None:
            self.metrics.add_size("Token", token.to_dict())

    def open_secure_channel_to_vs(self, cert_vs: Certificate, crl: CRL) -> SecureChannel:
        #verifica la validità del certificato del Voting Server e la non presenza del serial number del certificato nella CRL
        ok = verify_certificate(
            cert_vs,
            expected_role=ROLE_VS,
            election_id=self.params.election_id,
            ga_public_key_pem=self.params.ga_public_key_pem,
            crl=crl,
            metrics=self.metrics,
        )
        if not ok: #se il certificato non è valido, solleva un errore, NON E' POSSIBILE APRIRE UN CANALE SECURIZZATO AL VOTING SERVER
            #HARD FAIL
            raise ValueError("Voting Server certificate rejected")
        return SecureChannel()

    #funzione utilizzata per creare una busta di voto

    def prepare_ballot(self, preference: str) -> Ballot:
        #verifica che il token di voto sia disponibile
        if self.token is None:
            raise RuntimeError("No voting token available")

        #eventuale eccezione per preferenza non valida
        # if preference not in self.params.options:
        #     raise ValueError("Invalid preference for this election")

        # 1. Nonce della scheda locale
        nonce_ballot = generate_nonce()

         # 2. Voto in chiaro locale
        # Rimane nel client. VS ed ER non lo vedono.
        plaintext_vote = canonical_json(
            {
                "preference": preference,
            }
        ).encode("utf-8")

        #carica la chiave pubblica del Scrutiny Authority
        sa_public_key = load_public_key(self.params.scrutiny_public_key_pem)

        #cifro il voto con la chiave pubblica del Scrutiny Authority, in maniera non deterministica
        with self._measure("encrypt_vote"):
            encrypted_vote = rsa_encrypt(sa_public_key, plaintext_vote)
        encrypted_vote_b64 = b64e(encrypted_vote)
        #calcolo il commit del voto (deve combaciare con la verifica lato VS:
        #hash di election_id + ciphertext + nonce della scheda)
        ballot_commit = sha256_hex(
            json_bytes(
                {
                    "election_id": self.params.election_id,
                    "encrypted_vote_b64": encrypted_vote_b64,
                    "nonce_ballot": nonce_ballot,
                }
            )
        )
        self.ballot_commit = ballot_commit

        #creo l'oggetto Ballot
        unsigned = Ballot(
            election_id=self.params.election_id,
            token=self.token,
            voter_public_key_pem=self.public_key_pem,
            encrypted_vote_b64=encrypted_vote_b64,
            ballot_commit=ballot_commit,
            nonce_ballot=nonce_ballot,
            timestamp=now_ts(),
        )
        #firma il voto con la chiave privata dell'elettore
        with self._measure("sign"):
            signature = b64e(sign_message(self.private_key, json_bytes(unsigned.unsigned_payload_dict())))
        #aggiungo la firma al voto
        envelope = replace(unsigned, signature=signature)
        #aggiorno l'ultimo voto creato
        self.last_envelope = envelope
        if self.metrics is not None:
            #aggiorno le metriche con il voto creato
            self.metrics.add_size("Ballot", envelope.to_dict())
        #restituisco il voto creato completo di firma
        return envelope

    #funzione utilizzata per proteggere la busta di voto con il canale di comunicazione
    def protect_envelope(self, envelope: Ballot, channel: SecureChannel) -> bytes:
        return channel.protect(json_bytes(envelope.to_dict()))

#--------------------------------- VERIFICA DELLE RICEVUTE DI VOTO ---------------------------------#

    #funzione utilizzata per verificare la ricevuta di voto
    def verify_receipt(self, receipt: Receipt, cert_er: Certificate, crl: CRL) -> bool:
        #verifica la validità del certificato dell'Electoral Register
        if not verify_certificate(
            cert_er,
            expected_role=ROLE_ER,
            election_id=self.params.election_id,
            ga_public_key_pem=self.params.ga_public_key_pem,
            crl=crl,
            metrics=self.metrics,
        ):
            return False
        #carica la chiave pubblica dell'Electoral Register
        er_public_key = load_public_key(cert_er.public_key_pem)
        #verifica la firma della ricevuta con la chiave pubblica dell'Electoral Register
        with self._measure("verify_signature"):
            ok = verify_signature(er_public_key, json_bytes(receipt.payload_dict()), b64d(receipt.signature))
        if ok:
            self.last_receipt = receipt #aggiorna l'ultima ricevuta di voto
            if self.metrics is not None: #aggiorna le metriche con la ricevuta di voto
                self.metrics.add_size("Receipt", receipt.to_dict())
        return ok #ritorna True se la ricevuta è valida, False altrimenti


    #funzione utilizzata per verificare l'inclusione individuale di un record nell'albero Merkle
    def verify_individual_inclusion(
        self,
        record_data: str, #dati del record
        receipt: Receipt, #ricevuta di voto
        proof: MerkleProof, #prova Merkle
        root_final: str, #root finale
        cert_er: Certificate, #certificato dell'Electoral Register
        crl: CRL,
    ) -> bool:
        #verifica che l'ultimo voto sia disponibile
        if self.last_envelope is None:
            return False
        #verifica la validità della ricevuta di voto
        if not self.verify_receipt(receipt, cert_er, crl):
            return False
        #verifica che il commit della ricevuta corrisponda al commit del voto
        if receipt.ballot_commit != self.last_envelope.ballot_commit:
            return False
        #verifica che il hash del voto cifrato corrisponda al hash del voto cifrato nella ricevuta
        if sha256_hex(b64d(self.last_envelope.encrypted_vote_b64)) != receipt.encrypted_vote_hash:
            return False
        #verifica che il root finale corrisponda al root finale nella ricevuta
        if proof.root != root_final:
            return False
        #verifica la validità della prova Merkle
        with self._measure("merkle_verify_path"):
            #verifica la validità della prova Merkle
            ok = merkle.verify_proof(record_data, proof.path, root_final)
        if self.metrics is not None:
            #aggiorna le metriche con la prova Merkle
            self.metrics.add_size("MerkleProof", proof.to_dict())
        return ok #ritorna True se la prova Merkle è valida, False altrimenti
        #la recipt è valida ed il voto è stato inserito nell'albero Merkle
