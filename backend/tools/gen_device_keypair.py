#!/usr/bin/env python3
# tools/gen_device_keypair.py  
import oqs, base64, os
from pathlib import Path

# python tools/gen_device_keypair.py



OUT_DIR = Path("data/device_keys")
OUT_DIR.mkdir(parents=True, exist_ok=True)
PRIV_FILE = OUT_DIR / "device_priv.b64"

def main():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        pub = kem.generate_keypair()
        try:
            priv = kem.export_secret_key()
        except Exception:
            priv = None

    pub_b64 = base64.b64encode(pub).decode()
    if priv:
        PRIV_FILE.write_text(base64.b64encode(priv).decode())
        print("Private key saved to:", str(PRIV_FILE))
    else:
        print("Warning: private key export not available from this binding; store private key securely via device keygen method.")
    print("PUB_B64:", pub_b64)

if __name__ == "__main__":
    main()
    

