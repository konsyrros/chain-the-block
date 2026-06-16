# Lab 3: PoW Blockchain over IPv8

A 3-node Proof-of-Work blockchain built on top of the [py-ipv8](https://github.com/Tribler/py-ipv8) overlay network, developed for the TU Delft Blockchain Engineering course.

## Requirements

```bash
pip install -r requirements.txt
```

## Running

```bash
python lab3.py
```

All configuration has built-in defaults for our use case. Use the flags below to override any of them:

| Flag | Default | Description |
|---|---|---|
| `--member2-key` | Claudia's key | Hex public key of teammate 2 |
| `--member2-name` | `CLAUDIA` | Display name for teammate 2 |
| `--member3-key` | Ayush's key | Hex public key of teammate 3 |
| `--member3-name` | `AYUSH` | Display name for teammate 3 |
| `--server-key` | Lab 3 server key | Hex public key of the grading server |
| `--reg-community-id` | `4c616233...` | Hex ID of the registration community |
| `--blockchain-community-id` | `6b302474...` | Hex ID of your group's blockchain community |
| `--group-id` | `20abc108c3d58494` | Group ID used during registration |

Example with custom teammate keys and names, as well as custom group ID:

```bash
python lab3.py --member2-key <hex> --member2-name Alice --member3-key <hex> --member3-name Bob --group-id <hex>
```

Example with custom community IDs:

```bash
python lab3.py --reg-community-id <hex> --blockchain-community-id <hex>
```

The node uses `key.pem` in the current directory for its IPv8 identity (curve25519). This must be the same key registered in Labs 1 and 2. If the file with that name does not exist, a new one will be generated and saved. If you prefer to use a different filename, update on line 752 of `lab3.py`. Throughout the code, the runner's public key is dynamically derived.

## Architecture

### Registration

On startup the node joins two IPv8 communities simultaneously:

**Registration community (`TuDelftBlockchainLab3RegistrationCommunity`):**
Connects on the well-known community ID published by the course (`Lab3Blockchain2026PW`). Once all three group members and the grading server are visible as peers, any one node sends a `RegisterBlockchain` message to the server containing the group ID and the group's blockchain community ID. The server responds with `success=True`, joins the blockchain community, and begins grading attempts. Re-registration is allowed at any time and resets the server's retry counter.

**Blockchain community (`TuDelftBlockchainLab3Community`):**
Connects on the group's own community ID. Once all three nodes and the server are present here too, the node cancels the readiness poll, triggers a fresh registration (to confirm the server can detect all members), and starts the mining loop.

## Blockchain

### Block format

Each block header is 84 bytes:

```
prev_hash   (32 bytes)
txs_hash    (32 bytes)
timestamp   ( 8 bytes, uint64 big-endian)
difficulty  ( 4 bytes, uint32 big-endian)
nonce       ( 8 bytes, uint64 big-endian)
```

`block_hash = SHA256(header_bytes)`

The genesis block uses `prev_hash = 00...00`, `txs_hash = SHA256(b"")`, and timestamp/difficulty/nonce all 0, for a deterministic genesis block across all nodes.

### Proof of Work

Difficulty is expressed as a number of required leading zero bits. A block is valid when `block_hash < 2^(256 − difficulty)`. Mining increments the nonce until this holds. The current difficulty is set to **16**. If the chain tip changes while mining, the attempt is abandoned and a new one starts on the new tip. Difficulty can be updated on line 318 of `lab3.py` if desired.

### Transactions

`tx_hash = SHA256(sender_key || data || timestamp_8B_BE || signature)`

The body commitment stored in the header is `txs_hash = SHA256(tx_hash_1 || ... || tx_hash_n)`. An empty block uses `txs_hash = SHA256(b"")`. Incoming transactions are signature-verified with `ECCrypto` before entering the mempool, and relayed to all non-server peers.

### Fork choice and propagation

The chain is stored as a directed graph of blocks indexed by hash. On receiving a new block (mined locally or broadcast by a peer) the node:

1. Rejects it if the hash is already known (for deduplication).
2. Validates hash integrity, PoW, and txs_hash commitment.
3. Adds it to the block store and updates parent/child/height mappings.
4. Reconnects any orphans whose parent just arrived.
5. Switches `current_tip` to the longest complete chain.
6. Relays the block to all peers except the sender.

