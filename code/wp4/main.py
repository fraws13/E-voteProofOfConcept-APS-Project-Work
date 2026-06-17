"""Demo entry point for the WP4 e-voting PoC."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from crypto.certificates import verify_certificate
from core.config import (
    DEFAULT_ELECTION_ID,
    ELECTION_TYPE,
    ROLE_ER,
    ROLE_SA,
    ROLE_SA_NODE,
    ROLE_VS,
    SCRUTINY_NODES,
    SCRUTINY_THRESHOLD,
    DEFAULT_OPTIONS,
)
from crypto.crypto_utils import generate_rsa_key_pair, generate_nonce, public_key_to_pem
from electoral_register.electoral_register import ElectoralRegister
from datetime import datetime
from government_authority.government_authority import GovernmentAuthority
from core.metrics import MetricsCollector
from datetime import datetime, timedelta
from core.models import Certificate, CRL, ElectionParameters, Receipt
from scrutiny_authority.scrutiny_authority import ScrutinyAuthority, ScrutinyNode, generate_scrutiny_node
from core.verification import verify_universal_result
from voting_client.voting_client import VotingClient
from voting_server.voting_server import VotingServer

#classe utlizzata per creare l'ambiente di prova
#raccoglie tutti gli oggetti principali dell'elezione e gli da degli alias per facilitarne l'utilizzo
@dataclass
class Environment:
    ga: GovernmentAuthority
    vs: VotingServer
    er: ElectoralRegister
    sa: ScrutinyAuthority
    cert_vs: Certificate
    cert_er: Certificate
    cert_sa: Certificate
    crl: CRL
    params: ElectionParameters

#funzione utlizzata per creare l'ambiente di prova
'''eligible_users è una lista di utenti che sono eligibili per votare, definita nel durante l'esecuzione del benchmark'''
'''metrics è un oggetto MetricsCollector che viene utilizzato per misurare le metriche dell'elezione, se è None, non vengono misurate le metriche(modalità demo)'''

def build_environment(eligible_users: list[str], metrics: MetricsCollector | None = None) -> Environment:
    #definisci l'id dell'elezione
    election_id = DEFAULT_ELECTION_ID

    #crea l'istanza del Government Authority
    ga = GovernmentAuthority(eligible_users=eligible_users, metrics=metrics)

    # Infrastructure key pairs.
    #genera le chiavi per il Voting Server e l'Electoral Register
    #se non ci sono metriche, genera le chiavi senza misurare il tempo
    if metrics is None:
        vs_sk, vs_pk = generate_rsa_key_pair()
        er_sk, er_pk = generate_rsa_key_pair()
    #se ci sono metriche, genera le chiavi misurando il tempo
    else:
        with metrics.measure("key_generation"):
            vs_sk, vs_pk = generate_rsa_key_pair()
        with metrics.measure("key_generation"):
            er_sk, er_pk = generate_rsa_key_pair()

    #crea l'istanza del Voting Server e l'Electoral Register
    vs = VotingServer("VS-1", vs_sk, public_key_to_pem(vs_pk), metrics=metrics)
    #crea l'istanza dell'Electoral Register
    er = ElectoralRegister("ER-1", er_sk, public_key_to_pem(er_pk), metrics=metrics)
    #crea l'istanza del Scrutiny Authority
    sa = ScrutinyAuthority(threshold=SCRUTINY_THRESHOLD, node_count=SCRUTINY_NODES, metrics=metrics)

    #emette i certificati per il Voting Server, l'Electoral Register e il Scrutiny Authority
    cert_vs = ga.issue_certificate("VotingServer-1", ROLE_VS, election_id, vs.public_key_pem, organization_info='Voting Server', valid_from=datetime.now(), valid_to=datetime.now() + timedelta(days=2), nonce=generate_nonce(10))
    #emette il certificato per l'Electoral Register
    cert_er = ga.issue_certificate("ElectoralRegister-1", ROLE_ER, election_id, er.public_key_pem, organization_info='Electoral Register', valid_from=datetime.now(), valid_to=datetime.now() + timedelta(days=2), nonce=generate_nonce(10))
    #emette il certificato per il Scrutiny Authority
    cert_sa = ga.issue_certificate("ScrutinyAuthority", ROLE_SA, election_id, sa.public_key_pem, organization_info='Scrutiny Authority', valid_from=datetime.now(), valid_to=datetime.now() + timedelta(days=2), nonce=generate_nonce(10))
    #imposta il certificato per il Scrutiny Authority

    # La SA conserva internamente il proprio certificato perché lo usa nella fase di scrutinio.
    sa.set_certificate(cert_sa)

    #crea l'istanza dei nodi del Scrutiny Authority
    nodes: list[ScrutinyNode] = []
    #crea i nodi del Scrutiny Authority
    for i in range(SCRUTINY_NODES): #SCRUTINY_NODES è il numero di nodi del Scrutiny Authority, definito in config.py
        node_id = f"SA_NODE_{i + 1}"
        #genera le chiavi per il nodo del Scrutiny Authority
        node_sk, node_pk_pem = generate_scrutiny_node(node_id, metrics=metrics)
        #emette il certificato per il nodo del Scrutiny Authority
        cert_node = ga.issue_certificate(node_id, ROLE_SA_NODE, election_id, node_pk_pem, organization_info='Scrutiny Authority Node', valid_from=datetime.now(), valid_to=datetime.now() + timedelta(days=2), nonce=generate_nonce(10))
        #crea l'istanza del nodo del Scrutiny Authority
        nodes.append(ScrutinyNode(node_id=node_id, private_key=node_sk, public_key_pem=node_pk_pem, certificate=cert_node, metrics=metrics))
    #imposta i nodi del Scrutiny Authority
    sa.set_nodes(nodes)
    #crea il manifesto elettorale con i parametri dell'elezione
    params = ga.create_election_parameters(
        election_id=election_id,
        election_type=ELECTION_TYPE,
        options=DEFAULT_OPTIONS,
        opens_at=datetime.now(),
        closes_at=datetime.now() + timedelta(days=2),
        cert_vs=cert_vs,
        cert_er=cert_er,
        certs_sa= cert_node,
        scrutiny_nodes=SCRUTINY_NODES,
        scrutiny_threshold=SCRUTINY_THRESHOLD,
        scrutiny_public_key_pem=sa.public_key_pem,
        timestamp=datetime.now(),
    )
    crl = ga.current_crl(election_id)
    return Environment(ga=ga, vs=vs, er=er, sa=sa, cert_vs=cert_vs, cert_er=cert_er, cert_sa=cert_sa, crl=crl, params=params)

#funzione utlizzata per eseguire una demo dell'elezione
def demo() -> None:

    print("=== WP4 e-voting PoC: demo referendum binario ===")
    
    eligible_users = ["user-001", "user-002", "user-003"] #utenti che possono votare
    env = build_environment(eligible_users) #crea l'ambiente di prova
    
    opens_at = datetime.fromtimestamp(env.params.opens_at).strftime("%Y-%m-%d %H:%M:%S") #data e ora di apertura dell'elezione
    closes_at = datetime.fromtimestamp(env.params.closes_at).strftime("%Y-%m-%d %H:%M:%S") #data e ora di chiusura dell'elezione

    print("[1] Setup elezione completato")
    print("stampa il manifesto elettorale")
    print(env.params.to_dict())

    clients: list[VotingClient] = [] #lista di voting client che possono votare
    receipts: list[Receipt] = [] #lista di ricevute dei voti
    preferences = ["YES", "NO", "NO"] #preferenze dei voti

    print("\n[2] Autenticazione, emissione token, voto e registrazione") #stampa il numero di utenti che possono votare e le preferenze
    for user_id, preference in zip(eligible_users, preferences): #per ogni utente e preferenza, crea un voting client, emette un token, prepara un voto, apre un canale sicuro e registra il voto
        client = VotingClient(env.params)
        auth_request = client.build_auth_request()
        token = env.ga.request_voting_token(user_id, auth_request)
        client.store_and_verify_token(token)
        envelope = client.prepare_ballot(preference)
        channel = client.open_secure_channel_to_vs(env.cert_vs, env.crl)
        protected = client.protect_envelope(envelope, channel)
        receipt = env.vs.receive_secure_ballot(protected, channel, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        assert client.verify_receipt(receipt, env.cert_er, env.crl)
        clients.append(client)
        receipts.append(receipt)
        print(f"    {user_id}: voto cifrato registrato, leaf_hash={receipt.leaf_hash[:16]}...")

    print("\n[3] Controllo token spesi")
    print(f"    SpentTokensDB entries: {len(env.vs.spent_tokens_db)}")
    print(f"    Stati token: {[entry.status for entry in env.vs.spent_tokens_db.values()]}")

    print("\n[4] Chiusura urne e Merkle Tree")
    root_final = env.er.finalize()
    print(f"    Root_final: {root_final}")

    print("\n[5] Verifica individuale")
    for client, receipt in zip(clients, receipts):
        record_index = env.er.record_index_for_leaf_hash(receipt.leaf_hash)
        proof = env.er.get_merkle_proof(record_index)
        record_data = env.er.record_to_merkle_data(record_index)
        ok = client.verify_individual_inclusion(record_data, receipt, proof, root_final, env.cert_er, env.crl)
        print(f"    record {record_index}: {'OK' if ok else 'FAILED'}")

    print("\n[6] Scrutinio finale")
    authorizations = env.sa.collect_authorizations(env.params.election_id, root_final, len(env.er.records))
    result = env.sa.scrutinize(env.er.records, authorizations, env.params.election_id, root_final, env.params.ga_public_key_pem, env.crl)
    print(f"    count_yes={result.count_yes}, count_no={result.count_no}, count_invalid={result.count_invalid}")

    print("\n[7] Verifica universale simulata")
    universal_ok = verify_universal_result(env.er, result, env.cert_sa, env.crl, env.params.ga_public_key_pem)
    print(f"    Universal verification: {'OK' if universal_ok else 'FAILED'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WP4 e-voting Proof of Concept")
    parser.add_argument("--demo", action="store_true", help="run a small demonstrative election")
    parser.add_argument("--benchmark", action="store_true", help="run benchmark experiments")
    parser.add_argument("--tests", action="store_true", help="run built-in tests")
    args = parser.parse_args()

    if args.benchmark:
        from benchmark import run_benchmark

        run_benchmark()
    elif args.tests:
        import tests

        tests.run_all_tests()
    else:
        demo()


if __name__ == "__main__":
    main()
