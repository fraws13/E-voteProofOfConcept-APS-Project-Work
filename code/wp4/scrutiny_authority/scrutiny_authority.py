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
    sha256_hex,
    sign_message,
    verify_signature,
)
from core.metrics import MetricsCollector
from core.models import BoardRecord, Certificate, CRL, ScrutinyAuthorization, TallyResult

#classe che rappresenta un nodo di scrutinio
@dataclass
class ScrutinyNode:
    node_id: str
    private_key: object
    public_key_pem: str
    certificate: Certificate
    metrics: MetricsCollector | None = None

    #metodo che autorizza il scrutinio
    #il payload è il messaggio che viene inviato al nodo di scrutinio per autorizzarlo
    def authorize_scrutiny(self, election_id: str, root_final: str, m: int) -> ScrutinyAuthorization:
        payload = {
            "action": "AUTHORIZE_SCRUTINY",
            "election_id": election_id,
            "root_final": root_final,
            "m": m,
            "timestamp": now_ts(),
        }
        #in caso di metrics non è necessario misurare il tempo di esecuzione
        if self.metrics is None:
            signature = b64e(sign_message(self.private_key, json_bytes(payload)))
        else:
            with self.metrics.measure("sign"):
                signature = b64e(sign_message(self.private_key, json_bytes(payload)))
        #ogni nodo prudce una firma con il payload per autorizzare il scrutinio
        return ScrutinyAuthorization(
            node_id=self.node_id,
            certificate=self.certificate,
            payload=payload,
            signature=signature,
        )


#classe che rappresenta l'autorità di scrutinio
class ScrutinyAuthority:
    """
    non implementa la decrittazione a soglia matematica. La parte k-su-n.
    La parte k-su-n è simulata come una fase di autorizzazione distribuita: almeno k nodi SA certificati 
    devono firmare la stessa autorizzazione di verifica. Solo allora l'SA simulata
    decifra le schede elettorali con la chiave privata dell'elezione.
    """

    #il costruttore della classe ScrutinyAuthority
    def __init__(self, threshold: int, node_count: int, metrics: MetricsCollector | None = None) -> None:
        #verifica che il numero di nodi sia valido, 
        #ovvero che il numero di nodi sia maggiore di 0 e minore del numero totale di nodi<
        if threshold < 1 or threshold > node_count:
            raise ValueError("Invalid threshold parameters")
        self.threshold = threshold
        self.node_count = node_count
        self.metrics = metrics
        #genera la chiave privata e pubblica per l'autorità di scrutinio
        #chiave pubblica usata per la cifratura dei voti
        with self._measure("key_generation"):
            self.private_key, self.public_key = generate_rsa_key_pair()
        #converte la chiave pubblica in formato PEM, così da poterla inserire nel certificato e far si che possa essere utilizzata
        self.public_key_pem = public_key_to_pem(self.public_key)
        #il certificato dell'autorità di scrutinio
        self.certificate: Certificate | None = None
        #lista dei nodi di scrutinio
        self.nodes: list[ScrutinyNode] = []

    def _measure(self, name: str):
        if self.metrics is None:
            from contextlib import nullcontext

            return nullcontext()
        return self.metrics.measure(name)

    #metodo che imposta il certificato dell'autorità di scrutinio
    def set_certificate(self, certificate: Certificate) -> None:
        self.certificate = certificate

    #metodo che imposta i nodi di scrutinio
    def set_nodes(self, nodes: list[ScrutinyNode]) -> None:
        if len(nodes) != self.node_count:
            raise ValueError("Unexpected number of scrutiny nodes")
        self.nodes = nodes


    #metodo che raccoglie le autorizzazioni di scrutinio
    def collect_authorizations(self, election_id: str, root_final: str, m: int, how_many: int | None = None) -> list[ScrutinyAuthorization]:
        #seleziona i nodi di scrutinio, se how_many è None, seleziona threshold nodi,
        selected = self.nodes[: how_many or self.threshold]
        #ritorna la lista delle autorizzazioni di scrutinio
        return [node.authorize_scrutiny(election_id, root_final, m) for node in selected]


    #metodo che verifica le autorizzazioni di scrutinio
    def _valid_authorizations(
        self,
        authorizations: Iterable[ScrutinyAuthorization],
        election_id: str,
        root_final: str,
        m: int,
        ga_public_key_pem: str,
        crl: CRL,
    #ritorna la lista delle autorizzazioni di scrutinio valide
    ) -> list[ScrutinyAuthorization]:
        #lista delle autorizzazioni di scrutinio valide
        valid: list[ScrutinyAuthorization] = []
        #set dei nodi già visti
        seen_nodes: set[str] = set()

        #per ogni autorizzazione di scrutinio
        for auth in authorizations:
            #verifica che il nodo non sia già stato visitato
            if auth.node_id in seen_nodes:
                continue
            #verifica che l'id dell'elezione sia quello atteso
            if auth.payload.get("election_id") != election_id:
                continue
            #verifica che il root finale sia quello atteso
            if auth.payload.get("root_final") != root_final:
                continue
            #verifica che il numero di record sia quello atteso
            if auth.payload.get("m") != m:
                continue
            #verifica la validità del certificato
            if not verify_certificate(
                auth.certificate,
                expected_role=ROLE_SA_NODE,
                election_id=election_id,
                ga_public_key_pem=ga_public_key_pem,
                crl=crl,
                metrics=self.metrics,
            ):
                continue
            #carica la chiave pubblica del nodo
            node_public_key = load_public_key(auth.certificate.public_key_pem)
            with self._measure("verify_signature"):
                if verify_signature(node_public_key, json_bytes(auth.payload), b64d(auth.signature)):
                    #aggiunge l'autorizzazione di scrutinio alla lista delle autorizzazioni di scrutinio valide
                    valid.append(auth)
                    seen_nodes.add(auth.node_id)
        #ritorna la lista delle autorizzazioni di scrutinio valide
        return valid

    #metodo che scrutinizza i voti
    def scrutinize(
        #lista dei record del board
        self,
        records: list[BoardRecord],
        #lista delle autorizzazioni di scrutinio
        authorizations: list[ScrutinyAuthorization],
        #id dell'elezione
        election_id: str,
        #root finale
        root_final: str,
        #chiave pubblica dell'Government Authority
        ga_public_key_pem: str,
        #lista dei certificati revocati
        crl: CRL,
        #ritorna il risultato del scrutinio
    ) -> TallyResult:
        #misura il tempo di esecuzione
        with self._measure("scrutiny"):
            #verifica le autorizzazioni di scrutinio
            valid_authorizations = self._valid_authorizations(
                authorizations=authorizations, #lista delle autorizzazioni di scrutinio
                election_id=election_id,
                root_final=root_final, #root finale
                m=len(records), #numero di record
                ga_public_key_pem=ga_public_key_pem, #chiave pubblica dell'Government Authority
                crl=crl, #lista dei certificati revocati
            )
            #verifica che il numero di autorizzazioni di scrutinio valide sia maggiore o uguale al threshold
            if len(valid_authorizations) < self.threshold:
                raise PermissionError("Not enough valid Scrutiny Authority node authorizations")
            #inizializza i contatori dei voti
            count_yes = 0
            count_no = 0
            count_invalid = 0
            seen_ciphertext_hashes: set[str] = set()
            for i, record in enumerate(records):
                try:
                    #misura il tempo di esecuzione
                    with self._measure("decrypt_vote"):
                        #decifra il voto
                        plaintext = rsa_decrypt(self.private_key, b64d(record.Mboard.encrypted_vote_b64))
                    vote_data = json.loads(plaintext.decode("utf-8"))
                    #ottiene la preferenza del voto
                    preference = vote_data.get("preference")
                    #incrementa il contatore dei voti per la preferenza
                    if preference == "YES":
                        count_yes += 1
                    #incrementa il contatore dei voti per la preferenza NO
                    elif preference == "NO":
                        #incrementa il contatore dei voti per la preferenza NO
                        count_no += 1
                    else:
                        #incrementa il contatore dei voti per la preferenza non valida
                        count_invalid += 1
                except Exception:
                    #incrementa il contatore dei voti per la preferenza non valida
                    count_invalid += 1
            #crea l'oggetto TallyResult con i risultati del scrutinio
            unsigned = TallyResult(
                election_id=election_id,
                count_yes=count_yes,
                count_no=count_no,
                count_invalid=count_invalid,
                m=len(records),
                root_final=root_final,
                generated_at=now_ts(),
                authorizations=valid_authorizations, #lista delle autorizzazioni di scrutinio valide
            )
            with self._measure("sign"):
                signature = b64e(sign_message(self.private_key, json_bytes(unsigned.payload_dict())))
            #ritorna il risultato del scrutinio firmato
            return replace(unsigned, signature=signature)


#metodo che genera un nodo di scrutinio
def generate_scrutiny_node(node_id: str, certificate: Certificate | None = None, metrics: MetricsCollector | None = None) -> tuple[object, str]:
    if metrics is None:
        #genera la chiave privata e pubblica per il nodo di scrutinio
        private_key, public_key = generate_rsa_key_pair()
    else:
        with metrics.measure("key_generation"):
            private_key, public_key = generate_rsa_key_pair()
    return private_key, public_key_to_pem(public_key)
    #ritorna la chiave privata e pubblica del nodo di scrutinio
