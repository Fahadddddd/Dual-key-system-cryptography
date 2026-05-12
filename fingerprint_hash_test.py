import hashlib
from utils.biometric_utils import generate_salt, hash_biometric

print("\n==============================")
print(" FINGERPRINT HASH TEST")
print("==============================\n")

# Simulated fingerprint template
fingerprint_template = b"fingerprint_simulated_B"

# Generate random salt
salt = generate_salt()

# Hash fingerprint
fingerprint_hash = hash_biometric(fingerprint_template, salt)

print("Fingerprint Template:")
print(fingerprint_template)

print("\nSalt (HEX):")
print(salt.hex())

print("\nSHA-256 Fingerprint Hash:")
print(fingerprint_hash.hex())

print("\nHash Length:", len(fingerprint_hash) * 8, "bits")