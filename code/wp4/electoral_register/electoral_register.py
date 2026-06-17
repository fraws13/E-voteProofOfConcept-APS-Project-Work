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
        #non può essere aggiunto un record a un Bulletin Board finalizzato
        if self.finalized:
            #genera un errore se il Bulletin Board è finalizzato
            raise RuntimeError("Bulletin Board is finalized; no new record can be appended")

        #verifica la firma del Voting Server sul messaggio Mboard
        vs_public_key = load_public_key(vs_public_key_pem) #carica la chiave pubblica del Voting Server
        #verifica la firma del Voting Server sul messaggio Mboard
        with self._measure("verify_signature"):
            #se la firma del Voting Server sul messaggio Mboard non è valida, genera un errore
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
        #verifica che il commit della busta di voto corrisponda al commit dichiarato nel messaggio Mboard
        if ballot_commit != mboard.commit:
            #genera un errore se il commit della busta di voto non corrisponde al commit dichiarato nel messaggio Mboard
            raise ValueError("Mboard does not match ballot commit")
        #aggiunge il record al Bulletin Board
        with self._measure("board_registration"):
            #calcola il hash del record precedente
            previous_hash = self.records[-1].record_hash if self.records else "GENESIS"
            #per rispettare la proprietà di append-only, ogni record deve avere un indice univoco
            unsigned = BoardRecord(
                index=len(self.records),
                Mboard=mboard,
                timestamp_er=now_ts(),
                previous_record_hash=previous_hash,
                record_hash="",
            )
            #calcola il hash del record corrente
            record_hash = sha256_hex(json_bytes(unsigned.payload_dict()))
            record = BoardRecord(
                index=unsigned.index,
                Mboard=mboard,
                timestamp_er=unsigned.timestamp_er,
                previous_record_hash=unsigned.previous_record_hash,
                record_hash=record_hash,
            )
            #aggiunge il record alla bulletin board
            self.records.append(record)

        #crea la ricevuta di registrazione del record
        receipt_unsigned = Receipt(
            election_id=envelope.election_id, #id dell'elezione
            leaf_hash=record.record_hash, #hash del record
            ballot_commit=ballot_commit, #commit della busta di voto
            encrypted_vote_hash=sha256_hex(b64d(mboard.encrypted_vote_b64)),
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


    #funzione utilizzata per ottenere l'indice del record a partire dal hash della foglia
    def record_index_for_leaf_hash(self, leaf_hash: str) -> int:
        """Risolve l'indice interno a partire dal leaf_hash firmato nella receipt."""
        for i, record in enumerate(self.records):
            if record.record_hash == leaf_hash: #se il hash del record corrisponde al hash della foglia, restituisce l'indice
                return i
        #se non viene trovato il record, genera un errore
        raise ValueError(f"No board record found for leaf_hash={leaf_hash}")

    #funzione utilizzata per convertire il record in una stringa JSON
    def record_to_merkle_data(self, index: int) -> str:
        #converte il record in una stringa JSON
        return canonical_json(self.records[index].to_dict()) #converte il record in una stringa JSON
        #le foglie del Merkle tree devono essere stabili, quindi non possono cambiare durante l'aggiornamento dell'albero


    #funzione utilizzata per finalizzare l'albero Merkle finale e la Bulletin Board
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

    #funzione utilizzata per ottenere il proof di inclusione del record nell'albero Merkle di un certo record indice
    def get_merkle_proof(self, record_index: int) -> MerkleProof:
        #verifica che l'albero Merkle sia stato finalizzato
        if self.root_final is None or self._tree is None:
            #genera un errore se l'albero Merkle non è stato finalizzato
            raise RuntimeError("Bulletin Board has not been finalized")

        #genera il proof di inclusione del record nell'albero Merkle
        path = merkle.generate_proof(record_index, self._tree) #genera il proof di inclusione del record nell'albero Merkle
        proof = MerkleProof(record_index=record_index, root=self.root_final, path=path)
        if self.metrics is not None:
            #aggiunge le metriche del proof di inclusione del record nell'albero Merkle
            self.metrics.add_size("MerkleProof", proof.to_dict())
        #restituisce il proof di inclusione del record nell'albero Merkle
        return proof

    #funzione utilizzata per ricalcolare il root dell'albero Merkle finale
    #UTILE PER LE VERIFICHE DI SCRUTINIO
    def recompute_root(self) -> str:
        #genera la lista delle foglie dell'albero Merkle
        leaves = [self.record_to_merkle_data(i) for i in range(len(self.records))] #lista dei record convertiti in stringhe JSON
        #costruisce l'albero Merkle
        root, _ = merkle.build_merkle_tree(leaves)
        #restituisce il root dell'albero Merkle
        return root
