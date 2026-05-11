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


class BlockchainSettings(CommunitySettings):
    def __init__(self, member2_key: str = "", member3_key: str = "", **kwargs):
        super().__init__(**kwargs)
        self.member2_key = member2_key
        self.member3_key = member3_key

class RegisterMessage(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]

class RegisterResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]
    
class ChallengeRequest(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]
    
class ChallengeResponse(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]
    
class BundleSubmission(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]
    
class BundleResponse(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


class TuDelftBlockchainLab2Community(Community):
    community_id = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
    server_public_key = bytes.fromhex("4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96")
    settings_class = BlockchainSettings
    
    
    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        
        self.add_message_handler(RegisterResponse, self.handle_register_response)
        self.add_message_handler(ChallengeResponse, self.handle_challenge_response)
        self.add_message_handler(BundleResponse, self.handle_bundle_response)
        
        self.member1_key = self.my_peer.public_key.key_to_bin().hex()
        self.member2_key = settings.member2_key
        self.member3_key = settings.member3_key
        
        self.registered = False
        self.submitted = False
        
        self.group_id = None
        self.nonce = None
        self.deadline = None
        
        
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
            
            self.cancel_pending_task("start_communication")
            
        self.register_task("start_communication", start_communication, interval=2.0, delay=0)
        
    
    @lazy_wrapper(RegisterResponse)
    def handle_register_response(self, peer: Peer, message: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        print(f"Received register response: success={message.success}, group_id='{message.group_id}', message='{message.message}'") # type: ignore[attr-defined]
    
    
    @lazy_wrapper(ChallengeResponse)
    def handle_challenge_response(self, peer: Peer, message: ChallengeResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        print(f"Received challenge response: nonce='{message.nonce}', round_number={message.round_number}, deadline={message.deadline}") # type: ignore[attr-defined]

    
    @lazy_wrapper(BundleResponse)
    def handle_bundle_response(self, peer: Peer, message: BundleResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        print(f"Received bundle response: success={message.success}, round_number={message.round_number}, rounds_completed={message.rounds_completed}, message='{message.message}'") # type: ignore[attr-defined]


async def main():
    parser = argparse.ArgumentParser(description="Blockchain course lab 2 client.")
    args = parser.parse_args()
    
    member2_key = input("Enter public key of member 2: ")
    member3_key = input("Enter public key of member 3: ")
    
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "key.pem")
    builder.add_overlay(
        "TuDelftBlockchainLab2Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0})],
        default_bootstrap_defs,
        {"member2_key": member2_key, "member3_key": member3_key},
        [("started",)]
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"TuDelftBlockchainLab2Community": TuDelftBlockchainLab2Community})
    await ipv8.start()
    await run_forever()


if __name__ == "__main__":
    run(main())