# tools/allocate_unwrap_and_demo_otp.py
'''
python tools/allocate_unwrap_and_demo_otp.py \
  --sender_id "<DEVICE_ID>" \
  --recipient_id "<DEVICE_ID>" \
  --recipient_privfile "data/device_keys/device_priv.b64" \
  --message "Quantum-safe secret" \
  --length 100
'''


import argparse, base64, json, requests, sys, ctypes
from pathlib import Path
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://localhost:8000"
AAD = b"qmail-otp-wrap"  

def derive_aes_from_ss_for_otp(ss_bytes: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=AAD).derive(ss_bytes)

def try_decap(kem_name: str, priv_bytes: bytes, kem_ct_bytes: bytes) -> bytes:
    # 1) try two-arg style
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            return kem.decap_secret(priv_bytes, kem_ct_bytes)  # type: ignore
    except TypeError:
        pass
    # 2) fallback: set kem.secret_key = ctypes buffer and call decap_secret(ct)
    with oqs.KeyEncapsulation(kem_name) as kem:
        cbuf = ctypes.create_string_buffer(priv_bytes)
        kem.secret_key = cbuf  # type: ignore
        return kem.decap_secret(kem_ct_bytes)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sender_id", required=True)
    p.add_argument("--recipient_id", required=True)
    p.add_argument("--recipient_privfile", required=True)
    p.add_argument("--message", required=True)
    p.add_argument("--length", type=int, default=100)
    args = p.parse_args()

    # 1) Allocate OTP from backend
    payload = {
        "sender_device_id": args.sender_id,
        "recipient_device_id": args.recipient_id,
        "message_length": args.length
    }
    r = requests.post(f"{SERVER}/allocate-otp", json=payload)
    r.raise_for_status()
    res = r.json()
    print("Server response (km_key_id + wrapped_for_recipient):")
    print(json.dumps({k: res[k] for k in ("km_key_id","wrapped_for_recipient")}, indent=2))

    wrapped = res["wrapped_for_recipient"]
    kem_ct = base64.b64decode(wrapped["kem_ct_b64"])
    aes_ct = base64.b64decode(wrapped["aes_ct_b64"])
    nonce = base64.b64decode(wrapped["nonce_b64"])

    # 2) Load recipient private key
    priv_b64 = Path(args.recipient_privfile).read_text().strip()
    priv = base64.b64decode(priv_b64)

    # 3) Decapsulate -> shared secret
    kem_name = "Kyber512"
    ss = try_decap(kem_name, priv, kem_ct)
    print(f"[DEBUG] KEM: {kem_name}, Shared secret length: {len(ss)}")

    # 4) Derive AES key & unwrap OTP
    aes_key = derive_aes_from_ss_for_otp(ss)
    print("[DEBUG] Derived AES key (first 16 bytes b64):", base64.b64encode(aes_key[:16]).decode())

    try:
        otp = AESGCM(aes_key).decrypt(nonce, aes_ct, AAD)
    except Exception as e:
        print("AES unwrap failed:", e, file=sys.stderr)
        sys.exit(1)

    print(f"Unwrapped OTP length: {len(otp)}")
    print("OTP preview (first 16 bytes, b64):", base64.b64encode(otp[:16]).decode())

    # 5) Encrypt message with OTP (XOR)
    pt = args.message.encode()
    if len(pt) > len(otp):
        sys.exit("Message too long for allocated OTP.")
    ct = xor_bytes(pt, otp[:len(pt)])
    print("Ciphertext (b64):", base64.b64encode(ct).decode())

    # 6) Decrypt with same OTP
    recovered = xor_bytes(ct, otp[:len(pt)])
    print("Recovered plaintext:", recovered.decode())

    print("\nLevel-3 Successfull.")

if __name__ == "__main__":
    main()
