#!/usr/bin/env python3
# tools/allocate_and_unwrap_otp.py
import requests, base64, json, argparse
from pathlib import Path
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://localhost:8000"

def derive_aes_from_ss(ss_bytes: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-otp-wrap").derive(ss_bytes)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sender_id", required=True)
    p.add_argument("--recipient_id", required=True)
    p.add_argument("--recipient_privfile", required=True)
    p.add_argument("--message_length", type=int, default=100)
    args = p.parse_args()

    payload = {"sender_device_id": args.sender_id, "recipient_device_id": args.recipient_id, "message_length": args.message_length}
    r = requests.post(f"{SERVER}/allocate-otp", json=payload)
    r.raise_for_status()
    res = r.json()
    print("Server response (trimmed):", json.dumps({k: res[k] for k in ("km_key_id","wrapped_for_recipient")}, indent=2))

    # unwrap for recipient
    recipient_priv_b64 = Path(args.recipient_privfile).read_text().strip()
    priv = base64.b64decode(recipient_priv_b64)
    wrapped = res["wrapped_for_recipient"]
    kem_ct = base64.b64decode(wrapped["kem_ct_b64"])
    aes_ct = base64.b64decode(wrapped["aes_ct_b64"])
    nonce = base64.b64decode(wrapped["nonce_b64"])

    with oqs.KeyEncapsulation("Kyber512") as kem:
        ss = kem.decap_secret(priv, kem_ct) # type: ignore
    aes_key = derive_aes_from_ss(ss)
    aesgcm = AESGCM(aes_key)
    raw_otp = aesgcm.decrypt(nonce, aes_ct, b"qmail-otp-wrap")
    print("Unwrapped OTP length (bytes):", len(raw_otp))
    # Show first 32 bytes base64 (demo)
    print("OTP (first 32 bytes, b64):", base64.b64encode(raw_otp[:32]).decode())

if __name__ == "__main__":
    main()
