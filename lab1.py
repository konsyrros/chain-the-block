#!/usr/bin/env python3

import argparse

import hashlib

import os
from asyncio import run

from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, type_from_format
from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.peer import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8
from dataclasses import dataclass

class BlockchainSettings(CommunitySettings):
    def __init__(self, email: str = "", github: str = "", nonce: int = 0, **kwargs):
        super().__init__(**kwargs)
        self.email = email
        self.github = github
        self.nonce = nonce

@dataclass
class SubmissionMessage(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int

class ServerResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class TuDelftBlockchainCommunity(Community):
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
    server_public_key = bytes.fromhex("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb")
    settings_class = BlockchainSettings
    
    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ServerResponse, self.handle_response)
        self.submitted = False
        self.email = settings.email
        self.github = settings.github
        self.nonce = settings.nonce
        
    def started(self) -> None:
        print(f"Community ID: {self.community_id.hex()}")
        print(f"My peer: {self.my_peer}")
        
        async def start_communication() -> None:
            print("\nStarting communication task...")
            print(f"Found {len(self.get_peers())} peers.")
            print(f"Current peers: {[p.public_key.key_to_bin().hex() for p in self.get_peers()]}")
            if not self.submitted:
                payload = SubmissionMessage(
                    email=self.email,
                    github_url=self.github,
                    nonce=self.nonce
                )
                
                for p in self.get_peers():
                    if p.public_key.key_to_bin() == self.server_public_key:
                        print(f"Sending submission to peer {p.public_key.key_to_bin().hex()}...")
                        self.ez_send(p, payload)
                        self.submitted = True
                        break
                    else:
                        print(f"Peer {p.public_key.key_to_bin().hex()} does not match server public key.")
                else:
                    print("No peer with the community ID found. Waiting for peers to connect...")
            else:
                self.cancel_pending_task("start_communication")
        self.register_task("start_communication", start_communication, interval=2.0, delay=0)
        
    @lazy_wrapper(ServerResponse)
    def handle_response(self, peer: Peer, message: ServerResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        print(f"Received response: success={message.success}, message='{message.message}'") # type: ignore[attr-defined]

def find_nonce(payload: bytes, difficulty: int) -> int:
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder="big")
        combined_payload = payload + nonce_bytes
        if is_difficult(combined_payload, difficulty):
            return nonce
        nonce += 1

def is_difficult(payload: bytes, difficulty: int) -> bool:
    hash_bytes = hashlib.sha256(payload).digest()
    hash_int = int.from_bytes(hash_bytes, byteorder="big")
    return hash_int < (1 << (256 - difficulty))

async def main():
    parser = argparse.ArgumentParser(description="Blockchain course client.")
    parser.add_argument("--email", required=True, type=str, help="TU Delft email address.")
    parser.add_argument("--github", required=True, type=str, help="Public GitHub URL.")
    parser.add_argument("--nonce", type=int, help="Nonce value to use for the block.")
    parser.add_argument("--difficulty", type=int, default=28, help="PoW difficulty (number of leading zero bits).")
    args = parser.parse_args()
    
    print(f"Email: {args.email}")
    print(f"GitHub: {args.github}")
    
    payload = f"{args.email}\n{args.github}\n".encode()
    
    if args.nonce is not None:
        nonce_bytes = args.nonce.to_bytes(8, byteorder="big")
        block = payload + nonce_bytes
        if not is_difficult(block, args.difficulty):
            print("Provided nonce does not meet the difficulty requirement.")
            return
        print(f"Nonce verified: {args.nonce}")
        nonce = args.nonce
    else:
        print("Finding nonce...")
        nonce = find_nonce(payload, args.difficulty)
        print(f"Nonce found: {nonce}")
        nonce_bytes = nonce.to_bytes(8, byteorder="big")
        block = payload + nonce_bytes
        
    print(f"Block: {block.hex()}")
    print(f"Block hash: {hashlib.sha256(block).hexdigest()}")
    
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "key.pem")
    builder.add_overlay(
        "TuDelftBlockchainCommunity",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0})],
        default_bootstrap_defs,
        {"email": args.email, "github": args.github, "nonce": nonce},
        [("started",)]
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"TuDelftBlockchainCommunity": TuDelftBlockchainCommunity})
    await ipv8.start()
    my_peer_pubkey = ipv8.keys["my peer"].public_key.key_to_bin().hex()
    print(f"Public Key: {my_peer_pubkey}")
    await run_forever()
    
if __name__ == "__main__":
    run(main())