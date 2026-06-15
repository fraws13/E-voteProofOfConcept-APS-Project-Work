"""Electoral Register / Bulletin Board implementation."""

from __future__ import annotations

from core.config import ROLE_ER
from crypto.crypto_utils import b64d, b64e, canonical_json, json_bytes, load_public_key, now_ts, sha256_hex, sign_message, verify_signature
from core.metrics import MetricsCollector
from core.models import Ballot, BoardRecord, MerkleProof, Mboard, Receipt
import crypto.merkle as merkle

#classe utilizzata per creare un Electoral Register che permette di ricevere e verificare le buste di voto
class ElectoralRegister:
    """Append-only Bulletin Board for encrypted ballots."""

    def __init__(self, er_id: str, private_key, public_key_pem: str, metrics: MetricsCollector | None = None) -> None:
        self.er_id = er_id #id dell'Electoral Register
        self.private_key = private_key
        self.public_key_pem = public_key_pem #chiave pubblica dell'Electoral Register
        self.metrics = metrics #metriche dell'Electoral Register
        self.records: list[BoardRecord] = [] #lista dei record dell'Electoral Register
        self.finalized = False #flag che indica se l'Electoral Register è stato finalizzato
        self.root_final: str | None = None #hash dell'albero Merkle finale
        self._tree: list[list[str]] | None = None #albero Merkle

    def _measure(self, name: str):
        #misura le metriche dell'Electoral Register
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

#funzione utilizzata per aggiungere un record al Bulletin Board
    def append_record(self, envelope: Ballot, mboard: Mboard, vs_public_key_pem: str) -> Receipt:
        if self.finalized:
            raise RuntimeError("Bulletin Board is finalized; no new record can be appended")

        #verifica la firma del Voting Server sul messaggio Mboard
        vs_public_key = load_public_key(vs_public_key_pem) #
        with self._measure("verify_signature"):
            if not verify_signature(vs_public_key, json_bytes(mboard.payload_dict()), b64d(mboard.signature)):
                raise ValueError("Invalid VS signature on Mboard")
        #verifica la coerenza tra il messaggio Mboard e la busta di voto
        if mboard.election_id != envelope.election_id:
            raise ValueError("Mboard does not match election id")
        #calcola il commit della busta di voto
        ballot_commit = sha256_hex(
            json_bytes(
                {
                    "election_id": envelope.election_id,
                    "encrypted_vote_b64": envelope.encrypted_vote_b64,
                    "nonce_ballot": envelope.nonce_ballot,
                }
            )
        )
        if ballot_commit != mboard.commit:
            raise ValueError("Mboard does not match ballot commit")
        #aggiunge il record al Bulletin Board
        with self._measure("board_registration"):
            previous_hash = self.records[-1].record_hash if self.records else "GENESIS"
            #per rispettare la proprietà di append-only, ogni record deve avere un indice univoco
            unsigned = BoardRecord(
                index=len(self.records),
                election_id=envelope.election_id,
                encrypted_vote_b64=envelope.encrypted_vote_b64,
                ballot_commit=ballot_commit,
                timestamp_vs=mboard.timestamp,
                nonce_ballot=mboard.nonce_ballot,
                timestamp_er=now_ts(),
                previous_record_hash=previous_hash,
                record_hash="",
            )
            #calcola il hash del record corrente
            record_hash = sha256_hex(json_bytes(unsigned.payload_dict()))
            record = BoardRecord(**unsigned.payload_dict(), record_hash=record_hash) #crea il record completo
            #aggiunge il record alla bulletin board
            self.records.append(record)

        #crea la ricevuta di registrazione del record
        receipt_unsigned = Receipt(
            election_id=envelope.election_id,
            leaf_hash=record.record_hash, #hash del record
            ballot_commit=record.ballot_commit, #commit della busta di voto
            encrypted_vote_hash=sha256_hex(b64d(record.encrypted_vote_b64)), #hash del voto cifrato
            timestamp=now_ts(), #timestamp della ricevuta
        )
        #firma la ricevuta con la chiave privata dell'Electoral Register
        with self._measure("sign"):
            signature = b64e(sign_message(self.private_key, json_bytes(receipt_unsigned.payload_dict())))
        receipt = Receipt(**receipt_unsigned.payload_dict(), signature=signature)

        #aggiunge le metriche dei record e delle ricevute
        if self.metrics is not None:
            self.metrics.add_size("BoardRecord", record.to_dict()) #aggiunge le metriche del record
            self.metrics.add_size("Receipt", receipt.to_dict()) #aggiunge le metriche della ricevuta
        return receipt

    def record_index_for_leaf_hash(self, leaf_hash: str) -> int:
        """Risolve l'indice interno a partire dal leaf_hash firmato nella receipt."""
        for i, record in enumerate(self.records):
            if record.record_hash == leaf_hash:
                return i
        raise ValueError(f"No board record found for leaf_hash={leaf_hash}")

    def record_to_merkle_data(self, index: int) -> str:
        return canonical_json(self.records[index].to_dict()) #converte il record in una stringa JSON
        #le foglie del Merkle tree devono essere stabili, quindi non possono cambiare durante l'aggiornamento dell'albero


    #funzione utilizzata per finalizzare l'albero Merkle e la Bulletin Board
    def finalize(self) -> str:
        if not self.records:
            #non può essere finalizzato un Bulletin Board vuoto
            raise RuntimeError("Cannot finalize an empty Bulletin Board")
        #costruisce l'albero Merkle utilizzando le foglie convertite in stringhe JSON
        with self._measure("merkle_build"):
            #costruisce la lista delle foglie dell'albero Merkle
            leaves = [self.record_to_merkle_data(i) for i in range(len(self.records))] #lista dei record convertiti in stringhe JSON
            self.root_final, self._tree = merkle.build_merkle_tree(leaves) #costruisce l'albero Merkle
            self.finalized = True #setta il flag di finalizzazione
        return self.root_final #restituisce il hash dell'albero Merkle finale

    def get_merkle_proof(self, record_index: int) -> MerkleProof:
        if self.root_final is None or self._tree is None:
            raise RuntimeError("Bulletin Board has not been finalized")
        path = merkle.generate_proof(record_index, self._tree)
        proof = MerkleProof(record_index=record_index, root=self.root_final, path=path)
        if self.metrics is not None:
            self.metrics.add_size("MerkleProof", proof.to_dict())
        return proof

    def recompute_root(self) -> str:
        leaves = [self.record_to_merkle_data(i) for i in range(len(self.records))]
        root, _ = merkle.build_merkle_tree(leaves)
        return root
