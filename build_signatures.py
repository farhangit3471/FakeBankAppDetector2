import os
import hashlib
import json

# Folder where your malicious APKs are stored
MALICIOUS_APPS_DIR = "maliciousapps"
OUTPUT_FILE = "malicious_signatures.json"

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def build_signatures():
    signatures = {}
    for filename in os.listdir(MALICIOUS_APPS_DIR):
        if filename.endswith(".apk"):
            file_path = os.path.join(MALICIOUS_APPS_DIR, filename)
            file_hash = calculate_sha256(file_path)
            signatures[file_hash] = filename
            print(f"[+] Added {filename} → {file_hash}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(signatures, f, indent=4)

    print(f"\n✅ Signatures saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    build_signatures()
