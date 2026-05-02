#!/usr/bin/env python3

import argparse

import hashlib

import os
from asyncio import run

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8

def chain_the_block(payload: bytes, difficulty: int) -> bytes:
    nonce = find_nonce(payload, difficulty)
    return payload + nonce.to_bytes(8, byteorder="big")

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

def main():
    parser = argparse.ArgumentParser(description="Blockchain course client.")
    parser.add_argument("--email", type=str, help="TU Delft email address.")
    parser.add_argument("--github", type=str, help="Public GitHub URL.")
    parser.add_argument("--difficulty", type=int, default=28, help="PoW difficulty (number of leading zeros).")
    parser.add_argument("--nonce", type=int, help="Nonce value to use for the block.")
    parser.add_argument("--block", type=str, help="Precomputed block data in hex format.")
    args = parser.parse_args()
    
    print(f"Email: {args.email}")
    print(f"GitHub: {args.github}")
    
    payload = f"{args.email}\n{args.github}\n".encode()
    if args.block:
        block = bytes.fromhex(args.block)
    else:
        if args.nonce is not None:
            nonce_bytes = args.nonce.to_bytes(8, byteorder="big")
            block = payload + nonce_bytes
            if not is_difficult(block, args.difficulty):
                print("Provided nonce does not meet the difficulty requirement.")
                return
        else:
            block = chain_the_block(payload, difficulty=args.difficulty)
    print(f"Block: {block.hex()}")
    print(f"Block hash: {hashlib.sha256(block).hexdigest()}")
    
if __name__ == "__main__":
    main()