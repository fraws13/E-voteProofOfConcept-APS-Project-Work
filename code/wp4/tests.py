"""Minimal functional tests for the WP4 e-voting PoC."""

from __future__ import annotations

from dataclasses import replace

from core.config import ROLE_VS
from crypto.crypto_utils import b64d, b64e, canonical_json, generate_nonce, now_ts, rsa_encrypt, sha256_hex
from main import build_environment
from voting_client.voting_client import VotingClient
from core.verification import verify_universal_result

#Questa funzione simula un voto completo di un singolo elettore.
#dalla creazione dell'ambiente,
#  all'emissione del token, alla preparazione del voto, 
# all'apertura del canale sicuro e alla ricevuta della ricevuta.
def _cast_one_vote(user_id: str = "user-001", preference: str = "YES"):
    env = build_environment([user_id])
    client = VotingClient(env.params)
    auth_request = client.build_auth_request()
    token = env.ga.request_voting_token(user_id, auth_request)
    client.store_and_verify_token(token)
    envelope = client.prepare_ballot(preference)
    channel = client.open_secure_channel_to_vs(env.cert_vs, env.crl)
    protected = client.protect_envelope(envelope, channel)
    receipt = env.vs.receive_secure_ballot(protected, channel, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
    return env, client, envelope, receipt, channel, protected

#1 TEST: verifica che un elettore valido possa votare
def test_valid_voter_can_vote() -> None:
    #simula un voto completo di un singolo elettore
    env, client, envelope, receipt, *_ = _cast_one_vote()
    #verifica che il numero di record nell'albero Merkle sia 1
    assert len(env.er.records) == 1
    #verifica che il hash della foglia nell'albero Merkle corrisponda al hash del record
    assert receipt.leaf_hash == env.er.records[0].record_hash
    #verifica che la ricevuta sia valida
    assert client.verify_receipt(receipt, env.cert_er, env.crl)

#2 TEST: verifica che un elettore non abilitato non possa votare
def test_non_eligible_voter_gets_no_token() -> None:
    #crea l'ambiente
    env = build_environment(["user-001"])
    #crea un voting client
    client = VotingClient(env.params)
    try:
        #tenta di emettere un token a un elettore non abilitato
        env.ga.request_voting_token("user-NOT-ELIGIBLE", client.build_auth_request())
        #verifica che l'emissione del token fallisca
        assert False, "Expected token request to fail"
    except PermissionError:
        assert True

#3 TEST: verifica che un token non possa essere utilizzato più di una volta
def test_same_token_cannot_be_used_twice() -> None:
    env, client, envelope, receipt, *_ = _cast_one_vote()
    #prepara un secondo voto
    second_envelope = client.prepare_ballot("NO")
    #tenta di inviare il secondo voto
    try:
        #tenta di inviare il secondo voto a un voting server
        env.vs.receive_ballot(second_envelope, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        #verifica che l'invio del secondo voto fallisca
        assert False, "Expected token reuse to fail"
    #verifica che l'eccezione sia di tipo ValueError
    except ValueError as exc:
        assert "Token reuse" in str(exc)

#4 TEST: verifica che una firma alterata non possa essere accettata
def test_altered_signature_is_rejected() -> None:
    #crea l'ambiente
    env = build_environment(["user-001"])
    #crea un voting client
    client = VotingClient(env.params)
    #emette un token a un elettore valido
    Enctoken = env.ga.request_voting_token("user-001", client.build_auth_request())
    #verifica che il token sia valido
    client.store_and_verify_token(Enctoken)
    #prepara un voto
    envelope = client.prepare_ballot("YES")
    #altera la firma del voto
    tampered = replace(envelope, signature=b64e(b"invalid-signature"))
    #tenta di inviare il voto alterato a un voting server
    try:
        #tenta di inviare il voto alterato a un voting server
        env.vs.receive_ballot(tampered, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        #verifica che l'invio del voto alterato fallisca
        assert False, "Expected invalid signature to fail"
    #verifica che l'eccezione sia di tipo ValueError
    except ValueError as exc:
        assert "signature" in str(exc).lower()


#5 TEST: verifica che un record alterato non possa essere accettato
def test_tampered_record_fails_merkle_or_commitment_check() -> None:
    #simula un voto completo di un singolo elettore
    env, client, envelope, receipt, *_ = _cast_one_vote()
    #finalizza l'albero Merkle
    root = env.er.finalize()
    #genera la prova Merkle
    proof = env.er.get_merkle_proof(env.er.record_index_for_leaf_hash(receipt.leaf_hash))
    #altera il record all'interno del record BoardRecord
    tampered_dict = env.er.records[0].to_dict()
    #altera il commit del record
    tampered_dict["Mboard"]["commit"] = "00" * 32
    tampered_record_data = canonical_json(tampered_dict)
    #verifica che il record alterato non possa essere accettato
    assert not client.verify_individual_inclusion(tampered_record_data, receipt, proof, root, env.cert_er, env.crl)


#6 TEST: verifica che un certificato revocato non possa essere utilizzato
def test_revoked_certificate_is_rejected() -> None:
    #crea l'ambiente
    env = build_environment(["user-001"])
    #revoco il certificato del Voting Server
    env.ga.revoke_certificate(env.cert_vs)
    #genera la CRL corrente
    revoked_crl = env.ga.current_crl(env.params.election_id)
    #crea un voting client
    client = VotingClient(env.params)
    #tenta di aprire un canale sicuro al Voting Server con il certificato revocato
    try:
        #tenta di aprire un canale sicuro al Voting Server con il certificato revocato
        client.open_secure_channel_to_vs(env.cert_vs, revoked_crl)
        #verifica che l'apertura del canale sicuro fallisca
        assert False, "Expected revoked VS certificate to fail"
    #verifica che l'eccezione sia di tipo ValueError
    except ValueError as exc:
        #verifica che il messaggio dell'eccezione contenga la parola "certificate"
        assert "certificate" in str(exc).lower()


#7 TEST: verifica che un voto replayato non possa essere accettato
def test_replay_envelope_is_rejected() -> None:
    #simula un voto completo di un singolo elettore
    env, client, envelope, receipt, channel, protected = _cast_one_vote()
    try:
        #tenta di inviare il voto replayato a un voting server
        env.vs.receive_secure_ballot(protected, channel, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        #verifica che l'invio del voto replayato fallisca
        assert False, "Expected replay to fail"
    #verifica che l'eccezione sia di tipo ValueError
    except ValueError:
        assert True


#8 TEST: verifica che i conteggi del scrutinio siano coerenti
def test_scrutiny_counts_are_coherent() -> None:
    #crea l'ambiente
    env = build_environment(["user-001", "user-002", "user-003"])
    #per ogni elettore, emette un token, prepara un voto e invia il voto al voting server
    for user_id, pref in [("user-001", "YES"), ("user-002", "NO"), ("user-003", "YES")]:
        client = VotingClient(env.params)
        token = env.ga.request_voting_token(user_id, client.build_auth_request())
        client.store_and_verify_token(token)
        envelope = client.prepare_ballot(pref)
        env.vs.receive_ballot(envelope, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)

    #finalizza l'albero Merkle
    root = env.er.finalize()
    #raccolta le autorizzazioni per il scrutinio
    auths = env.sa.collect_authorizations(env.params.election_id, root, len(env.er.records))
    result = env.sa.scrutinize(env.er.records, auths, env.params.election_id, root, env.params.ga_public_key_pem, env.crl)
    #verifica che i conteggi del scrutinio siano coerenti
    assert result.count_yes == 2
    assert result.count_no == 1
    assert result.count_invalid == 0
    #verifica che il numero di voti sia pari al numero di record
    assert result.count_yes + result.count_no + result.count_invalid == len(env.er.records)
    #verifica che la verifica universale sia valida
    assert verify_universal_result(env.er, result, env.cert_sa, env.crl, env.params.ga_public_key_pem)

#esegue tutti i test
def run_all_tests() -> None:
    tests = [
        test_valid_voter_can_vote,
        test_non_eligible_voter_gets_no_token,
        test_same_token_cannot_be_used_twice,
        test_altered_signature_is_rejected,
        test_tampered_record_fails_merkle_or_commitment_check,
        test_revoked_certificate_is_rejected,
        test_replay_envelope_is_rejected,
        test_scrutiny_counts_are_coherent,
    ]
    for test in tests:
        test()
        print(f"[OK] {test.__name__}")
    print("All tests passed.")


if __name__ == "__main__":
    run_all_tests()
