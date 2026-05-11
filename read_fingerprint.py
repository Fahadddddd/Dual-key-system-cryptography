import serial
import hashlib

ser = serial.Serial('COM3', 115200)

template_hex = ""

print("Waiting for fingerprint template...")

while True:

    line = ser.readline().decode(errors='ignore').strip()

    if line == "BEGIN_TEMPLATE":
        template_hex = ""

        while True:
            line = ser.readline().decode(errors='ignore').strip()

            if line == "END_TEMPLATE":
                break

            template_hex += line

        break

print("\nFingerprint Template Received!\n")

print(template_hex[:100], "...")

# Convert HEX -> bytes
template_bytes = bytes.fromhex(template_hex)

# SHA-256
fingerprint_hash = hashlib.sha256(template_bytes).hexdigest()

print("\nSHA-256 Fingerprint Hash:")
print(fingerprint_hash)