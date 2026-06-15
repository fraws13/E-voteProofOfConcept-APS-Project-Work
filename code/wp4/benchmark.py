"""Benchmark runner for the WP4 e-voting PoC."""

from __future__ import annotations

import csv
import time
from pathlib import Path

from core.config import BENCHMARK_CSV, BENCHMARK_VOTER_COUNTS
from main import build_environment
from core.metrics import MetricsCollector
from core.verification import verify_universal_result
from voting_client.voting_client import VotingClient


CSV_COLUMNS = [
    "voters",
    "successful_votes",
    "key_generation_total_s",
    "signature_avg_s",
    "signature_verification_avg_s",
    "vote_encryption_avg_s",
    "vote_decryption_avg_s",
    "token_generation_avg_s",
    "token_verification_avg_s",
    "board_registration_avg_s",
    "merkle_build_total_s",
    "merkle_path_verification_avg_s",
    "scrutiny_total_s",
    "auth_request_avg_bytes",
    "token_avg_bytes",
    "ballot_envelope_avg_bytes",
    "board_record_avg_bytes",
    "receipt_avg_bytes",
    "merkle_proof_avg_bytes",
    "latency_per_vote_avg_s",
    "throughput_votes_per_second",
]


def run_experiment(voter_count: int) -> dict[str, float | int]:
    metrics = MetricsCollector()
    eligible_users = [f"user-id-{i:06d}" for i in range(voter_count)]
    env = build_environment(eligible_users, metrics=metrics)

    clients: list[VotingClient] = []
    receipts = []

    vote_phase_start = time.perf_counter()
    for i, user_id in enumerate(eligible_users):
        preference = "YES" if i % 2 == 0 else "NO"
        start_vote = time.perf_counter()

        client = VotingClient(env.params, metrics=metrics)
        auth_request = client.build_auth_request()
        token = env.ga.request_voting_token(user_id, auth_request)
        client.store_and_verify_token(token)
        envelope = client.prepare_ballot(preference)
        channel = client.open_secure_channel_to_vs(env.cert_vs, env.crl)
        protected = client.protect_envelope(envelope, channel)
        receipt = env.vs.receive_secure_ballot(
            protected,
            channel,
            env.er,
            env.cert_er,
            env.crl,
            env.params.ga_public_key_pem,
        )
        client.verify_receipt(receipt, env.cert_er, env.crl)

        metrics.add_time("latency_per_vote", time.perf_counter() - start_vote)
        clients.append(client)
        receipts.append(receipt)
    vote_phase_total = time.perf_counter() - vote_phase_start

    root_final = env.er.finalize()

    for client, receipt in zip(clients, receipts):
        record_index = env.er.record_index_for_leaf_hash(receipt.leaf_hash)
        proof = env.er.get_merkle_proof(record_index)
        record_data = env.er.record_to_merkle_data(record_index)
        ok = client.verify_individual_inclusion(record_data, receipt, proof, root_final, env.cert_er, env.crl)
        if not ok:
            raise RuntimeError("Unexpected failed individual verification during benchmark")

    authorizations = env.sa.collect_authorizations(env.params.election_id, root_final, len(env.er.records))
    result = env.sa.scrutinize(
        env.er.records,
        authorizations,
        env.params.election_id,
        root_final,
        env.params.ga_public_key_pem,
        env.crl,
    )
    if not verify_universal_result(env.er, result, env.cert_sa, env.crl, env.params.ga_public_key_pem, metrics=metrics):
        raise RuntimeError("Unexpected failed universal verification during benchmark")

    throughput = voter_count / vote_phase_total if vote_phase_total > 0 else 0.0
    return {
        "voters": voter_count,
        "successful_votes": len(receipts),
        "key_generation_total_s": metrics.total("key_generation"),
        "signature_avg_s": metrics.avg("sign"),
        "signature_verification_avg_s": metrics.avg("verify_signature"),
        "vote_encryption_avg_s": metrics.avg("encrypt_vote"),
        "vote_decryption_avg_s": metrics.avg("decrypt_vote"),
        "token_generation_avg_s": metrics.avg("token_generation"),
        "token_verification_avg_s": metrics.avg("token_verification"),
        "board_registration_avg_s": metrics.avg("board_registration"),
        "merkle_build_total_s": metrics.total("merkle_build"),
        "merkle_path_verification_avg_s": metrics.avg("merkle_verify_path"),
        "scrutiny_total_s": metrics.total("scrutiny"),
        "auth_request_avg_bytes": metrics.avg_size("AuthRequest"),
        "token_avg_bytes": metrics.avg_size("Token"),
        "ballot_envelope_avg_bytes": metrics.avg_size("Ballot"),
        "board_record_avg_bytes": metrics.avg_size("BoardRecord"),
        "receipt_avg_bytes": metrics.avg_size("Receipt"),
        "merkle_proof_avg_bytes": metrics.avg_size("MerkleProof"),
        "latency_per_vote_avg_s": metrics.avg("latency_per_vote"),
        "throughput_votes_per_second": throughput,
    }


def _fmt(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)
    return f"{value:.6f}"


def print_table(rows: list[dict[str, float | int]]) -> None:
    visible_columns = [
        "voters",
        "successful_votes",
        "latency_per_vote_avg_s",
        "throughput_votes_per_second",
        "merkle_build_total_s",
        "scrutiny_total_s",
        "ballot_envelope_avg_bytes",
    ]
    widths = {col: max(len(col), *(len(_fmt(row[col])) for row in rows)) for col in visible_columns}
    header = " | ".join(col.ljust(widths[col]) for col in visible_columns)
    print(header)
    print("-" * len(header))
    for row in rows:
        print(" | ".join(_fmt(row[col]).ljust(widths[col]) for col in visible_columns))


def write_csv(rows: list[dict[str, float | int]], output_path: str = BENCHMARK_CSV) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def run_benchmark(voter_counts: tuple[int, ...] = BENCHMARK_VOTER_COUNTS, output_path: str = BENCHMARK_CSV) -> None:
    print("=== WP4 benchmark ===")
    rows: list[dict[str, float | int]] = []
    for voters in voter_counts:
        print(f"Running experiment with {voters} voters...")
        rows.append(run_experiment(voters))
    print("\nBenchmark summary:")
    print_table(rows)
    write_csv(rows, output_path)
    print(f"\nCSV exported to: {Path(output_path).resolve()}")


if __name__ == "__main__":
    run_benchmark()
