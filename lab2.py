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

import logging


class IgnoreUnsupportedCurve(logging.Filter):
    def filter(self, record):
        if record.name != "TuDelftBlockchainLab2Community":
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


logger = logging.getLogger("TuDelftBlockchainLab2Community")
logger.addFilter(IgnoreUnsupportedCurve())


PUBLIC_KEYS = [
    "4c69624e61434c504b3a4924a5ac3d83e3128007c5a349dcbda9396f45fc0331f4cd84cf5b7ec3f7b20339cafc465a0f36ddb65c4295953d01327921d7ab4ea5a7e69dcb5e16b96e0ca3",
    "4c69624e61434c504b3a9063db4576026f2d41d5632e1be3d8f3d9acdea4e0f2676ef3bef35d4232d260a9c8cabef50ed898a2d0deb739982255f6c698996112ecef2350f945cae3d60a"
]


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
    
    
# Internal, intra-group signaling messages
class AnnounceChallenge(VariablePayload):
    msg_id = 100
    format_list = ["varlenHutf8", "varlenH", "d", "q"]
    names = ["group_id", "nonce", "deadline", "round_number"]
    
class BroadcastSignature(VariablePayload):
    msg_id = 102
    format_list = ["varlenH", "varlenH", "q"]
    names = ["nonce", "signature", "round_number"]
    
class BroadcastResult(VariablePayload):
    msg_id = 104
    format_list = ["varlenHutf8", "q", "?"]
    names = ["group_id", "round_number", "success"]


class TuDelftBlockchainLab2Community(Community):
    community_id = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
    server_public_key = bytes.fromhex("4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96")
    settings_class = BlockchainSettings
    
    
    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        
        self.add_message_handler(RegisterResponse, self.handle_register_response)
        self.add_message_handler(ChallengeResponse, self.handle_challenge_response)
        self.add_message_handler(BundleResponse, self.handle_bundle_response)
        
        self.add_message_handler(AnnounceChallenge, self.handle_announce_challenge)
        self.add_message_handler(BroadcastSignature, self.handle_broadcast_signature)
        self.add_message_handler(BroadcastResult, self.handle_broadcast_result)
        
        self.member1_key = self.my_peer.public_key.key_to_bin().hex()
        self.member2_key = settings.member2_key
        self.member3_key = settings.member3_key
        
        self.registered = False
        self.submitted = False
        
        self.group_id = None
        self.nonce = None
        self.deadline = None
        
        self.signatures = {}
        
        self.my_round = 1
        
        
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
            
            if not self.registered:
                print("Sending register message to server...")
                
                register_msg = RegisterMessage(member1_key=bytes.fromhex(self.member1_key), member2_key=bytes.fromhex(self.member2_key), member3_key=bytes.fromhex(self.member3_key))
                server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
                if not server_peer:
                    print("Server peer not found. Cannot send register message.")
                    return
                
                self.ez_send(server_peer, register_msg)
                
            self.cancel_pending_task("start_communication")

        self.register_task("start_communication", start_communication, interval=2.0, delay=0)
        
        
    def sign(self, nonce: bytes) -> bytes:
        crypto = ECCrypto()
        key = self.my_peer.key
        if key is None:
            raise ValueError("Private key is not available.")
        
        keyobj = crypto.key_from_private_bin(key.key_to_bin())
        if keyobj is None:
            raise ValueError("Failed to create key object from private key.")
        
        signature = keyobj.signature(nonce)
        return signature
    
    
    def get_peer_by_pubkey(self, pubkey_hex: str) -> Peer | None:
        for p in self.get_peers():
            if p.public_key.key_to_bin().hex() == pubkey_hex:
                return p
        return None
        
    
    @lazy_wrapper(RegisterResponse)
    def handle_register_response(self, peer: Peer, message: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        success = getattr(message, "success", False)
        group_id = getattr(message, "group_id", None)
        message_text = getattr(message, "message", "")
        
        print(f"Received register response: success={success}, group_id='{group_id}', message='{message_text}'")
        
        if not success:
            print("Registration failed. Cannot proceed.")
            return
        
        self.registered = True
        self.group_id = group_id
        
        print("Requesting challenge from server...")
        challenge_request = ChallengeRequest(group_id=self.group_id)
        server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
        if not server_peer:
            print("Server peer not found. Cannot send challenge request.")
            return
        self.ez_send(server_peer, challenge_request)
    
    
    @lazy_wrapper(ChallengeResponse)
    def handle_challenge_response(self, peer: Peer, message: ChallengeResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        nonce = getattr(message, "nonce", None)
        round_number = getattr(message, "round_number", None)
        deadline = getattr(message, "deadline", None)
        
        if nonce is None or round_number is None or deadline is None:
            print("Invalid challenge response. Missing fields.")
            return
        
        print(f"Received challenge response: nonce='{nonce.hex()}', round_number={round_number}, deadline={deadline}")
        
        self.nonce = nonce
        self.round_number = round_number
        self.deadline = deadline
        
        print("Announcing challenge to group members...")
        announce_msg = AnnounceChallenge(group_id=self.group_id, nonce=self.nonce, deadline=self.deadline, round_number=self.round_number)
        for p in self.get_peers():
            if p.public_key.key_to_bin() in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
                self.ez_send(p, announce_msg)
                
        signature = self.sign(self.nonce)
        self.signatures[self.my_peer.public_key.key_to_bin().hex()] = signature
        broadcast_msg = BroadcastSignature(nonce=self.nonce, signature=signature, round_number=self.round_number)
        for p in self.get_peers():
            if p.public_key.key_to_bin() in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
                self.ez_send(p, broadcast_msg)

    
    @lazy_wrapper(BundleResponse)
    def handle_bundle_response(self, peer: Peer, message: BundleResponse) -> None:
        if peer.public_key.key_to_bin() != self.server_public_key:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        success = getattr(message, "success", False)
        round_number = getattr(message, "round_number", None)
        rounds_completed = getattr(message, "rounds_completed", None)
        message_text = getattr(message, "message", "")
        
        print(f"Received bundle response: success={success}, round_number={round_number}, rounds_completed={rounds_completed}, message='{message_text}'")
        
        response_bcast = BroadcastResult(group_id=self.group_id, round_number=round_number, success=success)
        for p in self.get_peers():
            if p.public_key.key_to_bin() in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
                self.ez_send(p, response_bcast)
        
        if not success or round_number is None or rounds_completed is None:
            print("Invalid bundle response. Missing fields or unsuccessful.")
            return
        
        if rounds_completed >= 3:
            print("Challenge completed successfully!")
            exit(0)
        
        
    @lazy_wrapper(AnnounceChallenge)
    def handle_announce_challenge(self, peer: Peer, message: AnnounceChallenge) -> None:
        if peer.public_key.key_to_bin() not in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        if getattr(message, "round_number", None) != self.my_round:
            print(f"New round detected. Clearing signatures for round {getattr(message, 'round_number', None)}.")
            self.signatures.clear()
            self.my_round = getattr(message, "round_number", None)
        
        group_id = getattr(message, "group_id", None)
        nonce = getattr(message, "nonce", None)
        deadline = getattr(message, "deadline", None)
        round_number = getattr(message, "round_number", None)
        
        if group_id is None or nonce is None or deadline is None or round_number is None:
            print("Invalid challenge announcement. Missing fields.")
            return
        
        print(f"Received challenge announcement: group_id='{group_id}', nonce={nonce.hex()}, deadline={deadline}, round_number={round_number}")
        
        if group_id != self.group_id:
            print("Challenge announcement for different group. Ignoring.")
            return
        
        print("Announce challenge is valid. Signing nonce and broadcasting signature...")
        
        if self.my_peer.public_key.key_to_bin().hex() not in self.signatures:
            print("Signing nonce for the first time...")
            signature = self.sign(nonce)
            self.signatures[self.my_peer.public_key.key_to_bin().hex()] = signature
            
        signature = self.signatures[self.my_peer.public_key.key_to_bin().hex()]
        broadcast_msg = BroadcastSignature(nonce=nonce, signature=signature, round_number=round_number)
        for p in self.get_peers():
            if p.public_key.key_to_bin() in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
                self.ez_send(p, broadcast_msg)
                
        if len(self.signatures) == 3 and not self.submitted and round_number == self.my_round:
            print("All signatures collected for current round. Submitting bundle to server...")
            sig1 = self.signatures.get(bytes.fromhex(self.member1_key).hex(), b"")
            sig2 = self.signatures.get(bytes.fromhex(self.member2_key).hex(), b"")
            sig3 = self.signatures.get(bytes.fromhex(self.member3_key).hex(), b"")
            
            bundle_msg = BundleSubmission(group_id=self.group_id, round_number=round_number, sig1=sig1, sig2=sig2, sig3=sig3)
            server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
            if not server_peer:
                print("Server peer not found. Cannot send bundle submission.")
                return
            
            self.ez_send(server_peer, bundle_msg)
            self.submitted = True
        
        
    @lazy_wrapper(BroadcastSignature)
    def handle_broadcast_signature(self, peer: Peer, message: BroadcastSignature) -> None:
        if peer.public_key.key_to_bin() not in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        nonce = getattr(message, "nonce", None)
        signature = getattr(message, "signature", None)
        round_number = getattr(message, "round_number", None)
        
        if nonce is None or signature is None or round_number is None:
            print("Invalid broadcast signature message. Missing fields.")
            return
        
        print(f"Received signature broadcast: nonce={nonce.hex()}, signature={signature.hex()}, round_number={round_number}")
        self.signatures[peer.public_key.key_to_bin().hex()] = signature
        
        if len(self.signatures) == 3 and not self.submitted and round_number == self.my_round:
            print("All signatures collected for current round. Submitting bundle to server...")
            sig1 = self.signatures.get(bytes.fromhex(self.member1_key).hex(), b"")
            sig2 = self.signatures.get(bytes.fromhex(self.member2_key).hex(), b"")
            sig3 = self.signatures.get(bytes.fromhex(self.member3_key).hex(), b"")
            
            bundle_msg = BundleSubmission(group_id=self.group_id, round_number=round_number, sig1=sig1, sig2=sig2, sig3=sig3)
            server_peer = self.get_peer_by_pubkey(self.server_public_key.hex())
            if not server_peer:
                print("Server peer not found. Cannot send bundle submission.")
                return
            
            self.ez_send(server_peer, bundle_msg)
            self.submitted = True
            
            
    @lazy_wrapper(BroadcastResult)
    def handle_broadcast_result(self, peer: Peer, message: BroadcastResult) -> None:
        if peer.public_key.key_to_bin() not in [bytes.fromhex(self.member2_key), bytes.fromhex(self.member3_key)]:
            print(f"Received message from unknown peer {peer.public_key}. Ignoring.")
            return
        
        group_id = getattr(message, "group_id", None)
        round_number = getattr(message, "round_number", None)
        success = getattr(message, "success", None)
        
        if group_id is None or round_number is None or success is None:
            print("Invalid broadcast result message. Missing fields.")
            return
        
        print(f"Received broadcast result: group_id='{group_id}', round_number={round_number}, success={success}")


async def main():
    parser = argparse.ArgumentParser(description="Blockchain course lab 2 client.")
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