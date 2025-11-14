#!/usr/bin/env python3
"""
FINAL COMBINED SCRIPT
----------------------
AES-256-GCM Encryption + Biometric-Driven Dual Key System
Final Year Project – Sender-Side Prototype

Features:
1. Encrypt user message using AES-256-GCM.
2. Generate msgID (UUID).
3. Hash biometric data + salt.
4. Derive user key via HKDF (identity_hash + server_secret + msgID).
5. Encrypt session key for every recipient.
"""

import os
import base64
import uuid
import json
import argparse
import hashlib
import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ---------------------- Utility ----------------------
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')


def generate_k_sess():
    return os.urandom(32)


def generate_msg_id():
    return str(uuid.uuid4())


# ---------------------- Message Encryption ----------------------
def encrypt_message(key: bytes, plaintext: str, msg_id: str):

    plaintext_bytes = plaintext.encode('utf-8')
    aad = msg_id.encode('utf-8')

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    tag = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]

    return nonce, ciphertext, tag


# ---------------------- Biometric Dual Key System ----------------------
def generate_salt():
    return secrets.token_bytes(16)


def hash_biometric(biometric_data, salt):
    h = hashlib.sha256()
    h.update(biometric_data)
    h.update(salt)
    return h.digest()


def derive_user_key(identity_hash, server_secret, msg_id):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_secret,
        info=msg_id.encode(),
        backend=default_backend(),
    )
    return hkdf.derive(identity_hash)


def encrypt_session_key(derived_key, session_key):
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, session_key, None)
    return nonce, ciphertext


# ---------------------- MAIN ----------------------
def main():
    parser = argparse.ArgumentParser(description="AES + Biometric Dual Key System")
    parser.add_argument(
        "-m", "--message",
        required=True,
        help="Message to encrypt"
    )
    args = parser.parse_args()

    message = args.message

    print("\n===============================")
    print("   AES-256-GCM ENCRYPTION")
    print("===============================\n")

    # Step 1: Generate session key + msgID
    session_key = generate_k_sess()
    msgID = generate_msg_id()

    # Step 2: Encrypt message
    nonce, ciphertext, tag = encrypt_message(session_key, message, msgID)

    print("Message ID:", msgID)
    print("Session Key (Base64):", b64(session_key))
    print("Nonce:", b64(nonce))
    print("Ciphertext:", b64(ciphertext))
    print("Auth Tag:", b64(tag))

    encrypted_package = {
        "msgID": msgID,
        "ciphertext_b64": b64(ciphertext),
        "nonce_b64": b64(nonce),
        "tag_b64": b64(tag)
    }

    print("\nEncrypted Message Package (JSON):")
    print(json.dumps(encrypted_package, indent=2))

    # --------------------------------------------------------
    print("\n===============================")
    print("  BIOMETRIC-DRIVEN KEY WRAP")
    print("===============================\n")

    server_secret = secrets.token_bytes(32)

    recipients = {
        "user_A": b"fingerprint_simulated_A",
        "user_B": b"fingerprint_simulated_B",
        "user_C": b"fingerprint_simulated_C"
    }

    for user, biometric_data in recipients.items():

        salt = generate_salt()
        identity_hash = hash_biometric(biometric_data, salt)

        derived_key = derive_user_key(identity_hash, server_secret, msgID)

        wrap_nonce, wrapped_key = encrypt_session_key(derived_key, session_key)

        print(f"\nRecipient: {user}")
        print(f"  Salt: {salt.hex()}")
        print(f"  Identity Hash: {identity_hash.hex()[:20]}...")
        print(f"  Derived Key: {derived_key.hex()[:20]}...")
        print(f"  Wrap Nonce: {wrap_nonce.hex()}")
        print(f"  Wrapped Session Key: {wrapped_key.hex()[:40]}...")

    print("\n✅ Encryption + Key Wrapping Completed Successfully!\n")


if __name__ == "__main__":
    main()
