"""Minimal functional tests for the WP4 e-voting PoC."""

from __future__ import annotations

from dataclasses import replace

from core.config import ROLE_VS
from crypto.crypto_utils import b64d, b64e, canonical_json, generate_nonce, now_ts, rsa_encrypt, sha256_hex
from main import build_environment
from voting_client.voting_client import VotingClient
from core.verification import verify_universal_result

#test 1
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


def test_valid_voter_can_vote() -> None:
    env, client, envelope, receipt, *_ = _cast_one_vote()
    assert len(env.er.records) == 1
    assert receipt.leaf_hash == env.er.records[0].record_hash
    assert client.verify_receipt(receipt, env.cert_er, env.crl)


def test_non_eligible_voter_gets_no_token() -> None:
    env = build_environment(["student-001"])
    client = VotingClient(env.params)
    try:
        env.ga.request_voting_token("student-NOT-ELIGIBLE", client.build_auth_request())
        assert False, "Expected token request to fail"
    except PermissionError:
        assert True


def test_same_token_cannot_be_used_twice() -> None:
    env, client, envelope, receipt, *_ = _cast_one_vote()
    second_envelope = client.prepare_ballot("NO")
    try:
        env.vs.receive_ballot(second_envelope, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        assert False, "Expected token reuse to fail"
    except ValueError as exc:
        assert "Token reuse" in str(exc)


def test_altered_signature_is_rejected() -> None:
    env = build_environment(["student-001"])
    client = VotingClient(env.params)
    Enctoken = env.ga.request_voting_token("student-001", client.build_auth_request())
    client.store_and_verify_token(Enctoken)
    envelope = client.prepare_ballot("YES")
    tampered = replace(envelope, signature=b64e(b"invalid-signature"))
    try:
        env.vs.receive_ballot(tampered, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        assert False, "Expected invalid signature to fail"
    except ValueError as exc:
        assert "signature" in str(exc).lower()


def test_tampered_record_fails_merkle_or_commitment_check() -> None:
    env, client, envelope, receipt, *_ = _cast_one_vote()
    root = env.er.finalize()
    proof = env.er.get_merkle_proof(env.er.record_index_for_leaf_hash(receipt.leaf_hash))
    tampered_dict = env.er.records[0].to_dict()
    tampered_dict["ballot_commit"] = "00" * 32
    tampered_record_data = canonical_json(tampered_dict)
    assert not client.verify_individual_inclusion(tampered_record_data, receipt, proof, root, env.cert_er, env.crl)


def test_revoked_certificate_is_rejected() -> None:
    env = build_environment(["student-001"])
    env.ga.revoke_certificate(env.cert_vs)
    revoked_crl = env.ga.current_crl(env.params.election_id)
    client = VotingClient(env.params)
    try:
        client.open_secure_channel_to_vs(env.cert_vs, revoked_crl)
        assert False, "Expected revoked VS certificate to fail"
    except ValueError as exc:
        assert "certificate" in str(exc).lower()


def test_replay_envelope_is_rejected() -> None:
    env, client, envelope, receipt, channel, protected = _cast_one_vote()
    try:
        env.vs.receive_secure_ballot(protected, channel, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)
        assert False, "Expected replay to fail"
    except ValueError:
        assert True


def test_scrutiny_counts_are_coherent() -> None:
    env = build_environment(["user-001", "user-002", "user-003"])
    for user_id, pref in [("user-001", "YES"), ("user-002", "NO"), ("user-003", "YES")]:
        client = VotingClient(env.params)
        token = env.ga.request_voting_token(user_id, client.build_auth_request())
        client.store_and_verify_token(token)
        envelope = client.prepare_ballot(pref)
        env.vs.receive_ballot(envelope, env.er, env.cert_er, env.crl, env.params.ga_public_key_pem)

    root = env.er.finalize()
    auths = env.sa.collect_authorizations(env.params.election_id, root, len(env.er.records))
    result = env.sa.scrutinize(env.er.records, auths, env.params.election_id, root, env.params.ga_public_key_pem, env.crl)
    assert result.count_yes == 2
    assert result.count_no == 1
    assert result.count_invalid == 0
    assert result.count_yes + result.count_no + result.count_invalid == len(env.er.records)
    assert verify_universal_result(env.er, result, env.cert_sa, env.crl, env.params.ga_public_key_pem)


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
