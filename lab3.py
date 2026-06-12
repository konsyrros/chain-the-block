#!/usr/bin/env python3

import argparse

import asyncio
from asyncio import run
import threading

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
    "4c69624e61434c504b3a39ee7f7c6d5e4250e41b0a428ccd0ba344716db6c8882d088908739b6fad737c25ecb2419646b6763e87b7307d145919d35df26220f36ed0637b5ff86176ef91"
]

BLOCKCHAIN_COMMUNITY_ID_STR = "6b3024744024634c407540795524683477347233"


def pubkey_to_name(pubkey_hex: str) -> str:
    if pubkey_hex == "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6":
        return "SERVER"
    elif pubkey_hex == PUBLIC_KEYS[0]:
        return "CLAUDIA"
    elif len(PUBLIC_KEYS) > 1 and pubkey_hex == PUBLIC_KEYS[1]:
        return "AYUSH"
    else:
        return f"Unknown({pubkey_hex[:8]}...)"


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
    format_list = ["varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]
    
class NewBlockBroadcastResponse(VariablePayload):
    msg_id = 102
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "block_hash", "message"]
    
    
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
        self.add_message_handler(SubmitTransactionResponse, self.handle_submit_transaction_response)
        
        self.member1_key = self.my_peer.public_key.key_to_bin().hex()
        self.member2_key = settings.member2_key
        self.member3_key = settings.member3_key
        
        self.mempool = []
        self.current_tip = None
        
        self.blocks = {}    # all the blocks, including orphans, by hash
        self.children = {}  # mapping of a block hash to its children hashes
        self.tips = set()   # set of block hashes with no children
        self.parent = {}    # mapping of a block hash to its parent hash
        self.height = {}    # mapping of a block hash to its current height
        
        self.genesis = None
        
        self.generate_genesis_block()
        
        self.validated_tx_hashes = set()
        
        self.mining_interval = 30.0
        self.mining = False
        self.last_mined_tip = None
        
        
    async def mine(self):
        if self.mining:
            print("[MINE] Already mining a block. Skipping this mining interval.")
            return
        
        self.mining = True
        self.last_mined_tip = self.current_tip
        
        if self.last_mined_tip is None:
            print("[MINE] Current chain tip is unknown. Cannot start mining. Aborting mining attempt.")
            self.mining = False
            return
        
        included_hashes = []
        for tx in self.mempool:
            tx_hash = self.get_transaction_hash(*tx)
            if tx_hash not in self.validated_tx_hashes:
                included_hashes.append(tx_hash)
        
        print(f"[MINE] Creating new block with {len(included_hashes)} transactions.")
        
        cancel_event = threading.Event()
        self.cancel_mining_event = cancel_event
        
        prev_hash = self.last_mined_tip
        txs_hash = self.get_txs_hash(included_hashes)
        timestamp = int(time.time())
        difficulty = 16
        
        # nonce = await self.find_nonce(prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big"), difficulty)
        loop = asyncio.get_event_loop()
        nonce = await loop.run_in_executor(
            None, 
            lambda: self.find_nonce(prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big"), difficulty, cancel_event)
        )
        
        if nonce == -1:
            print("[MINE] Mining aborted due to chain tip change.")
            self.mining = False
            return
        
        block_hash = self.get_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce)
        
        new_block = {
            # "height": self.height[prev_hash] + 1 if prev_hash in self.height else 1,
            "prev_hash": prev_hash,
            "txs_hash": txs_hash,
            "timestamp": timestamp,
            "difficulty": difficulty,
            "nonce": nonce,
            "block_hash": block_hash,
            "tx_hashes": included_hashes,
        }
        # self.chain.append(new_block)
        self.add_block(new_block)
        self.validated_tx_hashes.update(included_hashes)
        
        print(f"[MINE] New block mined with hash {block_hash.hex()} containing {len(included_hashes)} transactions.")
        
        broadcast = NewBlockBroadcastMessage(
            # height=new_block["height"],
            prev_hash=new_block["prev_hash"],
            txs_hash=new_block["txs_hash"],
            timestamp=new_block["timestamp"],
            difficulty=new_block["difficulty"],
            nonce=new_block["nonce"],
            block_hash=new_block["block_hash"],
            tx_hashes=b"".join(included_hashes)
        )
        
        for p in self.get_peers():
            self.ez_send(p, broadcast)
            print(f"[MINE] Broadcasted new block with hash {block_hash.hex()} to peer {pubkey_to_name(p.public_key.key_to_bin().hex())}.")
        
        self.mining = False
        
        
    def calc_height(self, block_hash):
        # TODO: Perhaps we don't need the entire traversal here if we are already storing heights (unless orphans?)
        height = 0
        current_hash = block_hash
        while current_hash in self.parent:
            print(f"Parent of block {current_hash.hex()} is {self.parent[current_hash].hex()}.")
            current_hash = self.parent[current_hash]
            if current_hash == bytes.fromhex("00" * 32):
                print(f"Reached genesis block while calculating height for block {block_hash.hex()}.")
                break
            if current_hash in self.height:
                height += self.height[current_hash] + 1
                break
            height += 1
        
        return height
    
    
    def connect_orphans(self, block_hash):
        if block_hash not in self.children:
            return
        
        for child_hash in self.children[block_hash]:
            self.parent[child_hash] = block_hash
            self.height[child_hash] = self.calc_height(child_hash)
            
            if block_hash in self.tips:
                self.tips.remove(block_hash)
            
            self.connect_orphans(child_hash)
        
        
    def add_block(self, block):
        block_hash = block["block_hash"]
        self.blocks[block_hash] = block # Store the block by its hash
        
        prev_hash = block["prev_hash"]
        if prev_hash not in self.children:
            self.children[prev_hash] = [] # Initialize children list for the parent hash if it doesn't exist
        self.children[prev_hash].append(block_hash) # Add this block as a child of its parent
        
        if prev_hash in self.tips:
            self.tips.remove(prev_hash) # If the parent was a tip, it's no longer a tip since it has a child now
        self.tips.add(block_hash) # This new block is a tip until it gets a child
        
        self.parent[block_hash] = prev_hash
        self.height[block_hash] = self.calc_height(block_hash)
        
        self.connect_orphans(block_hash) # Connect any orphans that have this block as their parent
        
        current_tip_height = self.height[self.current_tip] if self.current_tip in self.height else -1
        highest_tip = max(self.tips, key=lambda h: self.height[h])
        if self.is_complete_chain(highest_tip) and self.height[highest_tip] > current_tip_height:
            print(f"Switching chain tip from {self.current_tip.hex() if self.current_tip else 'None'} at height {current_tip_height} to new tip {highest_tip.hex()} at height {self.height[highest_tip]} due to new block.")
            self.current_tip = highest_tip
            
            if hasattr(self, 'cancel_mining_event') and self.cancel_mining_event:
                self.cancel_mining_event.set()
            
        print(f"Added block with hash {block_hash.hex()} at height {self.height[block_hash]}. Current tip is {self.current_tip.hex() if self.current_tip else 'None'} at height {self.height[self.current_tip] if self.current_tip in self.height else 'Unknown'}. Parent {prev_hash.hex()}, {len(self.children[prev_hash])} children.")


    def get_chain_blocks(self, tip_hash):
        blocks = []
        current_hash = tip_hash
        while current_hash in self.blocks:
            block = self.blocks[current_hash]
            blocks.append(block)
            current_hash = block["prev_hash"]
        return list(reversed(blocks))
    
    
    def is_complete_chain(self, tip_hash):
        chain = self.get_chain_blocks(tip_hash)
        if not chain:
            return False
        if chain[0] != self.genesis:
            return False
        return True
            
        
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
            print("\nStarting blockchain communication task...")
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
            
            self.register_task("mine", self.mine, interval=self.mining_interval)
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
    
    
    def find_nonce(self, payload: bytes, difficulty: int, cancel_event: threading.Event) -> int:
        nonce = 0
        while True:
            if cancel_event.is_set():
                print("Mining cancelled.")
                return -1
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
            # "height": 0,
            "prev_hash": prev_hash,
            "txs_hash": txs_hash,
            "timestamp": timestamp,
            "difficulty": difficulty,
            "nonce": nonce,
            "block_hash": block_hash,
            "tx_hashes": []
        }
        
        # self.chain.append(genesis_block)
        self.add_block(genesis_block)
        self.current_tip = block_hash
        self.genesis = genesis_block
        print(f"Genesis block generated with hash {block_hash.hex()}")
            
            
    @lazy_wrapper(SubmitTransactionMessage)
    def handle_submit_transaction(self, peer: Peer, message: SubmitTransactionMessage) -> None:
        # Remove this if there is intra community gossip about transactions
        # if peer.public_key.key_to_bin() != self.server_public_key:
        #     print(f"[SUBMIT TX] Received message from unknown peer {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
        #     return
        
        if not all(hasattr(message, attr) for attr in ["sender_key", "data", "timestamp", "signature"]):
            print(f"[SUBMIT TX] Received malformed submit transaction message from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        sender_key = getattr(message, "sender_key")
        data = getattr(message, "data")
        timestamp = getattr(message, "timestamp")
        signature = getattr(message, "signature")
        
        # if sender_key != peer.public_key.key_to_bin():
        #     print(f"[SUBMIT TX] Sender key in message does not match peer public key for {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
        #     return

        crypto = ECCrypto()
        sender_key_obj = crypto.key_from_public_bin(sender_key)
        concat = sender_key + data + timestamp.to_bytes(8, "big")
        valid = crypto.is_valid_signature(sender_key_obj, concat, signature)
        
        tx_hash = self.get_transaction_hash(sender_key, data, timestamp, signature)
        
        if tx_hash in self.validated_tx_hashes:
            print(f"[SUBMIT TX] Received transaction with hash {tx_hash.hex()} from {pubkey_to_name(peer.public_key.key_to_bin().hex())} that has already been validated. Ignoring duplicate transaction.")
            response = SubmitTransactionResponse(success=False, tx_hash=tx_hash, message="Duplicate transaction already validated")
            self.ez_send(peer, response)
            return
        
        if any(tx_hash == self.get_transaction_hash(*tx) for tx in self.mempool):
            print(f"[SUBMIT TX] Received transaction with hash {tx_hash.hex()} from {pubkey_to_name(peer.public_key.key_to_bin().hex())} that is already in the mempool. Ignoring duplicate transaction.")
            response = SubmitTransactionResponse(success=False, tx_hash=tx_hash, message="Duplicate transaction in mempool")
            self.ez_send(peer, response)
            return
        
        if not valid:
            print(f"[SUBMIT TX] Received invalid transaction from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Rejecting.")
            response = SubmitTransactionResponse(success=False, tx_hash=tx_hash, message="Invalid transaction")
            self.ez_send(peer, response)
        
        print(f"[SUBMIT TX] Received valid transaction with hash {tx_hash.hex()} from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Adding to mempool.")
        self.mempool.append((sender_key, data, timestamp, signature))
        response = SubmitTransactionResponse(success=True, tx_hash=tx_hash, message="Transaction accepted")
        self.ez_send(peer, response)
        
        for p in self.get_peers():
            if p.public_key.key_to_bin() != peer.public_key.key_to_bin() and p.public_key.key_to_bin() != self.server_public_key:
                self.ez_send(p, message)
                print(f"[SUBMIT TX] Relayed transaction with hash {tx_hash.hex()} to peer {pubkey_to_name(p.public_key.key_to_bin().hex())}.")
            
            
    @lazy_wrapper(GetChainHeightMessage)
    def handle_get_chain_height(self, peer: Peer, message: GetChainHeightMessage) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"[GET HEIGHT] Received message from unknown peer {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        if not hasattr(message, "request_id"):
            print(f"[GET HEIGHT] Received malformed get chain height message from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        if not self.current_tip or self.current_tip not in self.height:
            print(f"[GET HEIGHT] Current chain tip is unknown or has invalid height. Cannot respond to get chain height request from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        request_id = getattr(message, "request_id")
        height = self.height[self.current_tip]
        tip_hash = self.current_tip
        
        response = GetChainHeightResponse(request_id=request_id, height=height, tip_hash=tip_hash)
        self.ez_send(peer, response)
        
        print(f"[GET HEIGHT] Received get chain height request with id {request_id} from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Responded with height {height} and tip hash {tip_hash.hex()}.")
    
    
    @lazy_wrapper(GetBlockMessage)
    def handle_get_block(self, peer: Peer, message: GetBlockMessage) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"[GET BLOCK] Received message from unknown peer {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        if not hasattr(message, "height"):
            print(f"[GET BLOCK] Received malformed get block message from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        height = getattr(message, "height")
        
        # if height < 0 or height >= len(self.chain):
        if height < 0 or height not in self.height.values():
            print(f"[GET BLOCK] Received get block message with invalid height {height} from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        # block = self.chain[height]
        # block = next((b for b in self.blocks.values() if self.height.get(b["block_hash"], -1) == height), None)
        active_chain = self.get_chain_blocks(self.current_tip) if self.current_tip else []
        block = active_chain[height] if height < len(active_chain) else None
        
        if not block:
            print(f"[GET BLOCK] Block at height {height} not found for get block request from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        response = GetBlockResponse(
            height=height,
            prev_hash=block["prev_hash"],
            txs_hash=block["txs_hash"],
            timestamp=block["timestamp"],
            difficulty=block["difficulty"],
            nonce=block["nonce"],
            block_hash=block["block_hash"],
            tx_hashes=b"".join(block["tx_hashes"])
        )
        self.ez_send(peer, response)
        
        print(f"[GET BLOCK] Received get block request for height {height} from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Responded with block hash {block['block_hash'].hex()} containing {len(block['tx_hashes']) // 32} transactions.")
        
        
    @lazy_wrapper(NewBlockBroadcastMessage)
    def handle_new_block_broadcast(self, peer: Peer, message: NewBlockBroadcastMessage) -> None:
        if not all(hasattr(message, attr) for attr in ["prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]):
            print(f"Received malformed new block broadcast message from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Ignoring.")
            return
        
        # height = getattr(message, "height")
        prev_hash = getattr(message, "prev_hash")
        txs_hash = getattr(message, "txs_hash")
        timestamp = getattr(message, "timestamp")
        difficulty = getattr(message, "difficulty")
        nonce = getattr(message, "nonce")
        block_hash = getattr(message, "block_hash")
        tx_hashes = getattr(message, "tx_hashes")
        
        print(f"[INTRA BLOCK] Received new block broadcast for block hash {block_hash.hex()} from {pubkey_to_name(peer.public_key.key_to_bin().hex())}. Block has {len(tx_hashes) // 32} transactions.")
        
        if block_hash != self.get_block_hash(prev_hash, txs_hash, timestamp, difficulty, nonce):
            print(f"[INTRA BLOCK] Block hash {block_hash.hex()} does not match computed hash from block data. Ignoring block.")
            response = NewBlockBroadcastResponse(success=False, block_hash=block_hash, message="Block hash does not match computed hash")
            self.ez_send(peer, response)
            return
        
        if not self.is_difficult(prev_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big") + nonce.to_bytes(8, "big"), difficulty):
            print(f"[INTRA BLOCK] Block does not meet difficulty requirement. Ignoring block.")
            response = NewBlockBroadcastResponse(success=False, block_hash=block_hash, message="Block does not meet difficulty requirement")
            self.ez_send(peer, response)
            return
        
        if txs_hash != hashlib.sha256(tx_hashes).digest():
            print(f"[INTRA BLOCK] Transactions hash does not match computed hash from transaction hashes. Ignoring block.")
            response = NewBlockBroadcastResponse(success=False, block_hash=block_hash, message="Transactions hash does not match computed hash")
            self.ez_send(peer, response)
            return
        
        # By this point the block hash matches the provided, the difficulty is met, and the hash of the transactions is also valid.
        
        # TODO: Decide if this is needed
        if any(tx_hashes[i:i+32] in self.validated_tx_hashes for i in range(0, len(tx_hashes), 32)):
            print(f"[INTRA BLOCK] Received block contains transactions that have already been validated. Ignoring block.")
            response = NewBlockBroadcastResponse(success=False, block_hash=block_hash, message="Block contains transactions that have already been validated")
            self.ez_send(peer, response)
            return
        
        self.add_block({
            # "height": height,
            "prev_hash": prev_hash,
            "txs_hash": txs_hash,
            "timestamp": timestamp,
            "difficulty": difficulty,
            "nonce": nonce,
            "block_hash": block_hash,
            "tx_hashes": [tx_hashes[i:i+32] for i in range(0, len(tx_hashes), 32)]
        })
        
        self.validated_tx_hashes.update(tx_hashes[i:i+32] for i in range(0, len(tx_hashes), 32))
        
        
    @lazy_wrapper(SubmitTransactionResponse)
    def handle_submit_transaction_response(self, peer: Peer, message: SubmitTransactionResponse) -> None:
        pass
    

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