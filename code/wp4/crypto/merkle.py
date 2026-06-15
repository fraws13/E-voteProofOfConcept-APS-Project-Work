"""Merkle Tree implementation used by the Bulletin Board."""

from __future__ import annotations

from crypto.crypto_utils import sha256_hex


def build_merkle_tree(data_list: list[str]) -> tuple[str, list[list[str]]]:
    """Build a Merkle Tree and return (root_hash, tree_levels)."""
    if not data_list:
        raise ValueError("data_list must not be empty")

    tree: list[list[str]] = [[sha256_hex(data) for data in data_list]]

    while len(tree[-1]) > 1:
        level = tree[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        parent_level = []
        for i in range(0, len(level), 2):
            parent_level.append(sha256_hex(level[i] + level[i + 1]))
        tree.append(parent_level)

    return tree[-1][0], tree


def generate_proof(leaf_index: int, tree: list[list[str]]) -> list[tuple[str, str]]:
    if leaf_index < 0 or leaf_index >= len(tree[0]):
        raise IndexError("leaf_index out of range")

    proof: list[tuple[str, str]] = []
    index = leaf_index

    for level in tree[:-1]:
        effective_level = level
        if len(effective_level) % 2 == 1:
            effective_level = effective_level + [effective_level[-1]]

        sibling_index = index ^ 1
        position = "right" if sibling_index > index else "left"
        proof.append((position, effective_level[sibling_index]))
        index //= 2

    return proof


def verify_proof(data: str, proof: list[tuple[str, str]], root: str) -> bool:
    current = sha256_hex(data)

    for position, sibling_hash in proof:
        if position == "right":
            current = sha256_hex(current + sibling_hash)
        elif position == "left":
            current = sha256_hex(sibling_hash + current)
        else:
            return False

    return current == root
