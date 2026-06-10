#!/usr/bin/env python3

import argparse

from asyncio import run

from ipv8.community import Community, CommunitySettings
from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.peer import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8
from ipv8.keyvault.crypto import ECCrypto
from cryptography.exceptions import UnsupportedAlgorithm

import hashlib
import time

import logging


class IgnoreUnsupportedCurve(logging.Filter):
    def filter(self, record):
        if record.name != "TuDelftBlockchainLab3Community" and record.name != "TuDelftBlockchainLab3RegistrationCommunity":
            return True

        if not record.exc_info:
            return True

        exc_type, exc, _ = record.exc_info
        
        if exc_type is None or exc is None:
            return True

        if (
            issubclass(exc_type, UnsupportedAlgorithm)
        ):
            return False

        return True


logger = logging.getLogger("TuDelftBlockchainLab3Community")
logger.addFilter(IgnoreUnsupportedCurve())

loggerreg = logging.getLogger("TuDelftBlockchainLab3RegistrationCommunity")
loggerreg.addFilter(IgnoreUnsupportedCurve())


PUBLIC_KEYS = [
    "4c69624e61434c504b3a4924a5ac3d83e3128007c5a349dcbda9396f45fc0331f4cd84cf5b7ec3f7b20339cafc465a0f36ddb65c4295953d01327921d7ab4ea5a7e69dcb5e16b96e0ca3",
    # "4c69624e61434c504b3a9063db4576026f2d41d5632e1be3d8f3d9acdea4e0f2676ef3bef35d4232d260a9c8cabef50ed898a2d0deb739982255f6c698996112ecef2350f945cae3d60a"
    # "4c69624e61434c504b3a8212fe4407ae6aa7d9ea6466cfe0e03b5b3169204e4566590275d38cdf447e5debe74ee90d60417c68fd15ff25e7bc3eea64c6b0112e618e183dae400c0c4385"
    # "4c69624e61434c504b3a2d1012b8df82cb92e938b1428a4ff5ac2eb29ac56bcb8b5aa16250e5619ce27e75397dac8a3a6b48e0a4dc55aeb002b202f670a29f39beab4e891d8da0ced0c0"
    "4c69624e61434c504b3a39ee7f7c6d5e4250e41b0a428ccd0ba344716db6c8882d088908739b6fad737c25ecb2419646b6763e87b7307d145919d35df26220f36ed0637b5ff86176ef91"
]

BLOCKCHAIN_COMMUNITY_ID_STR = "434c41554449414c414233424c4f434b32363030"


class BlockchainRegistrationSettings(CommunitySettings):
    def __init__(self, group_id = "", member2_key: str = "", member3_key: str = "", **kwargs):
        super().__init__(**kwargs)
        self.group_id = group_id
        self.member2_key = member2_key
        self.member3_key = member3_key

class BlockchainSettings(CommunitySettings):
    def __init__(self, member2_key: str = "", member3_key: str = "", **kwargs):
        super().__init__(**kwargs)
        self.member2_key = member2_key
        self.member3_key = member3_key
        
# Registration Messages (Part 1)
class RegisterMessage(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]

class RegisterResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]
    
# Server Messages (Part 2)
class SubmitTransactionMessage(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]
    
class SubmitTransactionResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]
    
class GetChainHeightMessage(VariablePayload):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]
    
class GetChainHeightResponse(VariablePayload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]
    
class GetBlockMessage(VariablePayload):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]
    
class GetBlockResponse(VariablePayload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]
    
# Intra-community Messages
class NewBlockBroadcastMessage(VariablePayload):
    msg_id = 101
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]
    
    
class TuDelftBlockchainLab3RegistrationCommunity(Community):
    community_id = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
    server_public_key = bytes.fromhex("4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6")
    settings_class = BlockchainRegistrationSettings
    
    
    def __init__(self, settings: BlockchainRegistrationSettings) -> None:
        super().__init__(settings)
        
        self.add_message_handler(RegisterResponse, self.handle_register_response)
        
        self.group_id = settings.group_id
        self.member1_key = self.my_peer.public_key.key_to_bin().hex()
        self.member2_key = settings.member2_key
        self.member3_key = settings.member3_key
        
        self.registered = False
        
        
    def is_ready(self) -> bool:
        peers = self.get_peers()
        
        found_server = any(p.public_key.key_to_bin() == self.server_public_key for p in peers)
        found_member2 = any(p.public_key.key_to_bin() == bytes.fromhex(self.member2_key) for p in peers)
        found_member3 = any(p.public_key.key_to_bin() == bytes.fromhex(self.member3_key) for p in peers)
        
        if found_server:
            print("Found server peer.")
            
        if found_member2:
            print("Found member 2 peer.")
            
        if found_member3:
            print("Found member 3 peer.")
        
        return found_server and found_member2 and found_member3
    
    
    def get_peer_by_pubkey(self, pubkey_hex: str) -> Peer | None:
        for p in self.get_peers():
            if p.public_key.key_to_bin().hex() == pubkey_hex:
                return p
        return None
    
    
    def started(self) -> None:
        print(f"Community ID: {self.community_id.hex()}")
        print(f"My peer: {self.my_peer}")
        print(f"My public key: {self.my_peer.public_key.key_to_bin().hex()}")
        
        async def start_communication() -> None:
            print("\nStarting registration communication task...")
            print(f"Found {len(self.get_peers())} peers.")
            
            if not self.is_ready():
                print("Not all required peers are present. Waiting for peers to connect for registration...")
                return
            
            if not self.registered:                
                register_msg = RegisterMessage(group_id=self.group_id, community_id=bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID_STR))
                server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
                if not server_peer:
                    print("Server peer not found. Cannot send register message.")
                    return
                
                print("Sending register message to server...")
                
                self.ez_send(server_peer, register_msg)
                
            self.cancel_pending_task("start_communication")

        self.register_task("start_communication", start_communication, interval=2.0, delay=0)
        
        
    @lazy_wrapper(RegisterResponse)
    def handle_register_response(self, peer: Peer, message: RegisterResponse) -> None:
        if self.registered:
            return
        
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        success = getattr(message, "success", False)
        message_text = getattr(message, "message", "")
        
        print(f"Received register response: success={success}, message='{message_text}'")
        
        if success:
            print("===== Registration successful. =====")
            self.registered = True
    

class TuDelftBlockchainLab3Community(Community):
    community_id = bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID_STR)
    server_public_key = bytes.fromhex("4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6")
    settings_class = BlockchainSettings
    
    
    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        
        self.add_message_handler(SubmitTransactionMessage, self.handle_submit_transaction)
        self.add_message_handler(GetChainHeightMessage, self.handle_get_chain_height)
        self.add_message_handler(GetBlockMessage, self.handle_get_block)
        self.add_message_handler(NewBlockBroadcastMessage, self.handle_new_block_broadcast)
        
        self.member1_key = self.my_peer.public_key.key_to_bin().hex()
        self.member2_key = settings.member2_key
        self.member3_key = settings.member3_key
        
        self.mempool = []
        self.chain = []
        
        self.generate_genesis_block()
        
        
    def is_ready(self) -> bool:
        peers = self.get_peers()
        
        found_server = any(p.public_key.key_to_bin() == self.server_public_key for p in peers)
        found_member2 = any(p.public_key.key_to_bin() == bytes.fromhex(self.member2_key) for p in peers)
        found_member3 = any(p.public_key.key_to_bin() == bytes.fromhex(self.member3_key) for p in peers)
        
        if found_server:
            print("Found server peer.")
            
        if found_member2:
            print("Found member 2 peer.")
            
        if found_member3:
            print("Found member 3 peer.")
        
        return found_server and found_member2 and found_member3
    
    
    def get_peer_by_pubkey(self, pubkey_hex: str) -> Peer | None:
        for p in self.get_peers():
            if p.public_key.key_to_bin().hex() == pubkey_hex:
                return p
        return None
        
        
    def started(self) -> None:
        print(f"Community ID: {self.community_id.hex()}")
        print(f"My peer: {self.my_peer}")
        print(f"My public key: {self.my_peer.public_key.key_to_bin().hex()}")
        
        async def start_communication() -> None:
            print("\nStarting communication task...")
            print(f"Found {len(self.get_peers())} peers.")
            
            if not self.is_ready():
                print("Not all required peers are present. Waiting for peers to connect...")
                return
            
            # if not self.registered:
            #     print("Sending register message to server...")
                
            #     register_msg = RegisterMessage(member1_key=bytes.fromhex(self.member1_key), member2_key=bytes.fromhex(self.member2_key), member3_key=bytes.fromhex(self.member3_key))
            #     server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
            #     if not server_peer:
            #         print("Server peer not found. Cannot send register message.")
            #         return
                
            #     self.ez_send(server_peer, register_msg)
                
            self.cancel_pending_task("start_communication")

        self.register_task("start_communication", start_communication, interval=2.0, delay=0)
        
        
    def get_block_hash(self, prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
        data = prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big") + nonce.to_bytes(8, "big")
        return hashlib.sha256(data).digest()
    
    
    def get_transaction_hash(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
        data = sender_key + data + timestamp.to_bytes(8, "big") + signature
        return hashlib.sha256(data).digest()
    
    
    def get_txs_hash(self, tx_hashes: list[bytes]) -> bytes:
        if not tx_hashes or len(tx_hashes) == 0:
            return hashlib.sha256(b"").digest()
        
        combined = b"".join(tx_hashes)
        return hashlib.sha256(combined).digest()
    
    
    def is_difficult(self, payload: bytes, difficulty: int) -> bool:
        hash_bytes = hashlib.sha256(payload).digest()
        hash_int = int.from_bytes(hash_bytes, byteorder="big")
        return hash_int < (1 << (256 - difficulty))
    
    
    def find_nonce(self, payload: bytes, difficulty: int) -> int:
        nonce = 0
        while True:
            nonce_bytes = nonce.to_bytes(8, byteorder="big")
            combined_payload = payload + nonce_bytes
            if self.is_difficult(combined_payload, difficulty):
                return nonce
            nonce += 1
            
            
    def generate_genesis_block(self) -> None:
        print("Generating genesis block...")
        prev_hash = bytes.fromhex("00" * 32)
        txs_hash = hashlib.sha256(b"").digest()
        timestamp = 0
        difficulty = 0
        nonce = 0
        block_hash = self.get_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        
        genesis_block = {
            "height": 0,
            "prev_hash": prev_hash,
            "txs_hash": txs_hash,
            "timestamp": timestamp,
            "difficulty": difficulty,
            "nonce": nonce,
            "block_hash": block_hash,
            "tx_hashes": []
        }
        
        self.chain.append(genesis_block)
        print(f"Genesis block generated with hash {block_hash.hex()}")
            
            
    @lazy_wrapper(SubmitTransactionMessage)
    def handle_submit_transaction(self, peer: Peer, message: SubmitTransactionMessage) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        if not all(hasattr(message, attr) for attr in ["sender_key", "data", "timestamp", "signature"]):
            print(f"Received malformed submit transaction message from {peer.public_key}. Ignoring.")
            return
        
        sender_key = getattr(message, "sender_key")
        data = getattr(message, "data")
        timestamp = getattr(message, "timestamp")
        signature = getattr(message, "signature")
        
        if sender_key != peer.public_key.key_to_bin():
            print(f"Sender key in message does not match peer public key for {peer.public_key}. Ignoring.")
            return

        crypto = ECCrypto()
        sender_key_obj = crypto.key_from_public_bin(sender_key)
        concat = sender_key + data + timestamp.to_bytes(8, "big")
        valid = crypto.is_valid_signature(sender_key_obj, concat, signature)
        
        if not valid:
            print(f"Received invalid transaction from {peer.public_key}. Rejecting.")
            response = SubmitTransactionResponse(success=False, tx_hash=tx_hash, message="Invalid transaction")
            self.ez_send(peer, response)
        
        tx_hash = self.get_transaction_hash(sender_key, data, timestamp, signature)
        
        print(f"Received valid transaction with hash {tx_hash.hex()} from {peer.public_key}. Adding to mempool.")
        self.mempool.append((sender_key, data, timestamp, signature))
        response = SubmitTransactionResponse(success=True, tx_hash=tx_hash, message="Transaction accepted")
        self.ez_send(peer, response)
        
        if len(self.mempool) >= 10:
            print("Mempool has 10 transactions. Creating new block...")
            mempool_copy = self.mempool.copy()
            self.mempool.clear()
            mempool_hashes = [self.get_transaction_hash(*tx) for tx in mempool_copy]
            prev_hash = self.chain[-1]["block_hash"]
            txs_hash = self.get_txs_hash(mempool_hashes)
            timestamp = int(time.time())
            difficulty = 4
            nonce = self.find_nonce(prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big"), difficulty)
            block_hash = self.get_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
            
            new_block = {
                "height": len(self.chain),
                "prev_hash": prev_hash,
                "txs_hash": txs_hash,
                "timestamp": timestamp,
                "difficulty": difficulty,
                "nonce": nonce,
                "block_hash": block_hash,
                "tx_hashes": mempool_hashes,
            }
            self.chain.append(new_block)
            
            print(f"New block created with hash {block_hash.hex()} containing {len(mempool_copy)} transactions.")
            
            broadcast = NewBlockBroadcastMessage(
                height=new_block["height"],
                prev_hash=new_block["prev_hash"],
                txs_hash=new_block["txs_hash"],
                timestamp=new_block["timestamp"],
                difficulty=new_block["difficulty"],
                nonce=new_block["nonce"],
                block_hash=new_block["block_hash"],
                tx_hashes=b"".join(mempool_hashes)
            )
            
            for p in self.get_peers():
                self.ez_send(p, broadcast)
                print(f"Broadcasted new block with hash {block_hash.hex()} to peer {p.public_key}.")
            
            
    @lazy_wrapper(GetChainHeightMessage)
    def handle_get_chain_height(self, peer: Peer, message: GetChainHeightMessage) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        if not hasattr(message, "request_id"):
            print(f"Received malformed get chain height message from {peer.public_key}. Ignoring.")
            return
        
        request_id = getattr(message, "request_id")
        height = len(self.chain) - 1
        # tail = self.chain[-1]
        # if not hasattr(tail, "block_hash"):
        #     print(f"Current chain tip block is malformed. Cannot get tip hash. Ignoring get chain height request.")
        #     return
        tip_hash = self.chain[-1]["block_hash"]
        
        response = GetChainHeightResponse(request_id=request_id, height=height, tip_hash=tip_hash)
        self.ez_send(peer, response)
        
        print(f"Received get chain height request with id {request_id} from {peer.public_key}. Responded with height {height} and tip hash {tip_hash.hex()}.")
    
    
    @lazy_wrapper(GetBlockMessage)
    def handle_get_block(self, peer: Peer, message: GetBlockMessage) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        if not hasattr(message, "height"):
            print(f"Received malformed get block message from {peer.public_key}. Ignoring.")
            return
        
        height = getattr(message, "height")
        
        if height < 0 or height >= len(self.chain):
            print(f"Received get block message with invalid height {height} from {peer.public_key}. Ignoring.")
            return
        
        block = self.chain[height]
        
        response = GetBlockResponse(
            height=block["height"],
            prev_hash=block["prev_hash"],
            txs_hash=block["txs_hash"],
            timestamp=block["timestamp"],
            difficulty=block["difficulty"],
            nonce=block["nonce"],
            block_hash=block["block_hash"],
            tx_hashes=b"".join(block["tx_hashes"])
        )
        self.ez_send(peer, response)
        
        print(f"Received get block request for height {height} from {peer.public_key}. Responded with block hash {block['block_hash'].hex()} containing {len(block['tx_hashes']) // 32} transactions.")
        
        
    @lazy_wrapper(NewBlockBroadcastMessage)
    def handle_new_block_broadcast(self, peer: Peer, message: NewBlockBroadcastMessage) -> None:
        if not all(hasattr(message, attr) for attr in ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]):
            print(f"Received malformed new block broadcast message from {peer.public_key}. Ignoring.")
            return
        
        height = getattr(message, "height")
        prev_hash = getattr(message, "prev_hash")
        txs_hash = getattr(message, "txs_hash")
        timestamp = getattr(message, "timestamp")
        difficulty = getattr(message, "difficulty")
        nonce = getattr(message, "nonce")
        block_hash = getattr(message, "block_hash")
        tx_hashes = getattr(message, "tx_hashes")
        
        print(f"Received new block broadcast for block hash {block_hash.hex()} at height {height} from {peer.public_key}. Block has {len(tx_hashes) // 32} transactions.")
        
        if block_hash != self.get_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce):
            print(f"Block hash {block_hash.hex()} does not match computed hash from block data. Ignoring block.")
            return
        
        if not self.is_difficult(prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big") + nonce.to_bytes(8, "big"), difficulty):
            print(f"Block does not meet difficulty requirement. Ignoring block.")
            return
        
        if txs_hash != hashlib.sha256(tx_hashes).digest():
            print(f"Transactions hash does not match computed hash from transaction hashes. Ignoring block.")
            return
        
        # By this point the block hash matches the provided, the difficulty is met, and the hash of the transactions is also valid.
        # Must now understand if this block extends, overtakes, or is behind the tip.
        
        if height < len(self.chain):
            print(f"Received block is at height {height} which is behind current chain height {len(self.chain) - 1}. Ignoring block.")
            return
        
        if height == len(self.chain):
            if prev_hash != self.chain[-1]["block_hash"]:
                print(f"Received block does not extend current chain tip. Ignoring block.")
                return
            
            print(f"Received block extends current chain tip. Adding block to chain.")
            new_block = {
                "height": height,
                "prev_hash": prev_hash,
                "txs_hash": txs_hash,
                "timestamp": timestamp,
                "difficulty": difficulty,
                "nonce": nonce,
                "block_hash": block_hash,
                "tx_hashes": [tx_hashes[i:i+32] for i in range(0, len(tx_hashes), 32)]
            }
            self.chain.append(new_block)
            
            for p in self.get_peers():
                if p.public_key.key_to_bin() != peer.public_key.key_to_bin():
                    self.ez_send(p, message)
                    print(f"Re-broadcasted new block with hash {block_hash.hex()} to peer {p.public_key}.")
            
            return
        
        # FORKING
    

async def main():
    parser = argparse.ArgumentParser(description="Blockchain course lab 3 client.")
    args = parser.parse_args()
    
    if not PUBLIC_KEYS or len(PUBLIC_KEYS) < 2:
        member2_key = input("Enter public key of member 2: ")
        member3_key = input("Enter public key of member 3: ")
    else:
        member2_key = PUBLIC_KEYS[0]
        member3_key = PUBLIC_KEYS[1]
    
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "key.pem")
    builder.add_overlay(
        "TuDelftBlockchainLab3Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0})],
        default_bootstrap_defs,
        {"member2_key": member2_key, "member3_key": member3_key},
        [("started",)]
    )
    builder.add_overlay(
        "TuDelftBlockchainLab3RegistrationCommunity",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0})],
        default_bootstrap_defs,
        {"group_id": "20abc108c3d58494", "member2_key": member2_key, "member3_key": member3_key},
        [("started",)]
    )

    ipv8 = IPv8(
        builder.finalize(), extra_communities={
            "TuDelftBlockchainLab3Community": TuDelftBlockchainLab3Community,
            "TuDelftBlockchainLab3RegistrationCommunity": TuDelftBlockchainLab3RegistrationCommunity
        }
    )
    await ipv8.start()
    await run_forever()


if __name__ == "__main__":
    run(main())