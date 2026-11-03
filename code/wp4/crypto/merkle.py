"""Merkle Tree implementation used by the Bulletin Board."""

from __future__ import annotations

from crypto.crypto_utils import sha256_hex

# Costruisce un Merkle Tree da una lista di dati e restituisce 
# la radice dell'albero e i livelli dell'albero.
def build_merkle_tree(data_list: list[str]) -> tuple[str, list[list[str]]]:
    # Se la lista è vuota lancia un errore
    if not data_list:
        raise ValueError("data_list must not be empty")

    # Prima foglia: hash dei dati di partenza
    tree: list[list[str]] = [[sha256_hex(data) for data in data_list]]

    # Ciclo che costruisce ogni livello dell'albero fino a che non resta una sola radice
    while len(tree[-1]) > 1:
        level = tree[-1]
        # Se il numero di nodi è dispari, duplica l'ultimo nodo per poterlo accoppiare
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        parent_level = []
        # Accoppia gli elementi due a due e calcola l'hash concatenato (nodo genitore)
        for i in range(0, len(level), 2):
            parent_level.append(sha256_hex(level[i] + level[i + 1]))
        tree.append(parent_level)

    # Ritorna la radice e l'intero albero (tutti i livelli)
    return tree[-1][0], tree

# Genera il Merkle proof per verificare che una foglia specifica sia nell'albero
def generate_proof(leaf_index: int, tree: list[list[str]]) -> list[tuple[str, str]]:
    # Controlla che l'indice della foglia sia valido
    if leaf_index < 0 or leaf_index >= len(tree[0]):
        raise IndexError("leaf_index out of range")

    proof: list[tuple[str, str]] = []
    index = leaf_index

    # Per ogni livello (tranne l'ultimo, che è la radice)
    for level in tree[:-1]:
        effective_level = level
        # Se il livello ha elementi dispari, duplica l'ultimo per il calcolo
        if len(effective_level) % 2 == 1:
            effective_level = effective_level + [effective_level[-1]]

        sibling_index = index ^ 1  # Trova l'indice del fratello
        # Se il fratello è a destra o a sinistra
        position = "right" if sibling_index > index else "left"
        # Aggiungi alla proof la posizione e l'hash del fratello
        proof.append((position, effective_level[sibling_index]))
        # Vai al livello superiore (indice // 2)
        index //= 2

    return proof

# Verifica che una determinata foglia sia inclusa nel Merkle Tree a partire dalla proof e dalla radice
def verify_proof(data: str, proof: list[tuple[str, str]], root: str) -> bool:
    # Calcola l'hash della foglia di partenza
    current = sha256_hex(data)

    # Per ogni step della proof, ricostruisce la catena degli hash fino a risalire alla radice
    for position, sibling_hash in proof:
        if position == "right":
            current = sha256_hex(current + sibling_hash)
        elif position == "left":
            current = sha256_hex(sibling_hash + current)
        else:
            return False  # In caso di posizione non valida

    # Alla fine, se il valore risulta uguale alla radice, la proof è valida
    return current == root
