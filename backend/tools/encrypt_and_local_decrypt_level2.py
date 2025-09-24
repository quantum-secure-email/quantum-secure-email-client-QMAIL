#!/usr/bin/env python3
# tools/encrypt_and_local_decrypt_level2.py
"""
Robust end-to-end Level-2 demo (server-side encapsulation + device-side decapsulation).
This version tries multiple liboqs-python decapsulation call shapes:
  1) kem.decap_secret(priv, ct)
  2) set kem.secret_key = ctypes.create_string_buffer(priv); kem.decap_secret(ct)
and reports diagnostics if neither works.
"""
import requests, base64, json, argparse
from pathlib import Path
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import ctypes

SERVER = "http://localhost:8000"

def derive_aes_from_ss(ss_bytes: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-aes").derive(ss_bytes)

def try_decap_with_various_signatures(kem_name: str, priv_bytes: bytes, kem_ct_bytes: bytes):
    """
    Try several common liboqs-python decapsulation call shapes.
    Returns shared_secret_bytes on success, or raises RuntimeError with helpful debug info.
    """
    # 1) Try legacy two-arg call: kem.decap_secret(priv, ct)
    try:
        with oqs.KeyEncapsulation(kem_name) as kemtemp:
            try:
                ss = kemtemp.decap_secret(priv_bytes, kem_ct_bytes)
                return ss
            except TypeError:
                # signature mismatch for this binding; fallthrough
                pass
            except Exception as e:
                # decap_secret raised an error (wrong priv format etc.) — record and continue
                last_exc = e
    except Exception:
        last_exc = None

    # 2) Some bindings expect the instance to hold the secret key (kem.secret_key) as a ctypes buffer
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            # if the kem reports expected secret key length, check it
            expected_len = getattr(kem, "length_secret_key", None)
            if expected_len is not None:
                if len(priv_bytes) != expected_len:
                    # warn but still try — some bindings include padding/format differences
                    print(f"WARNING: private key length ({len(priv_bytes)}) != kem.length_secret_key ({expected_len}). Attempting to continue...", file=sys.stderr)

            # create a ctypes buffer from the bytes
            try:
                cbuf = ctypes.create_string_buffer(priv_bytes)  # correct ctypes object
            except Exception as e:
                raise RuntimeError(f"Failed to create ctypes buffer for private key: {e}") from e

            # assign the ctypes buffer to kem.secret_key (binding will use ctypes.byref on it)
            try:
                setattr(kem, "secret_key", cbuf)
            except Exception as e:
                raise RuntimeError(f"Failed to set kem.secret_key attribute: {e}") from e

            # Now call decap_secret with only the capsule
            try:
                ss = kem.decap_secret(kem_ct_bytes)
                return ss
            except Exception as e:
                # final failure for this approach
                raise RuntimeError(f"decap_secret(ct) after setting kem.secret_key failed: {e}") from e
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Could not instantiate/operate KeyEncapsulation for '{kem_name}': {e}") from e

def inspect_kem_methods(kem_name: str):
    out = {}
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            out["dir"] = [a for a in dir(kem) if not a.startswith("_")]
            out["has_setters"] = {s: hasattr(kem, s) for s in ("import_secret_key","set_secret_key","create_keypair_from_secret","load_secret_key")}
            for attr in ("length_public_key","length_secret_key","length_shared_secret","length_ciphertext"):
                if hasattr(kem, attr):
                    try:
                        out[attr] = getattr(kem, attr)
                    except Exception:
                        out[attr] = "error_reading"
    except Exception as e:
        out["error"] = str(e)
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--device_id", required=True, help="recipient device id registered on server")
    p.add_argument("--privfile", required=True, help="path to recipient private key file (base64)")
    p.add_argument("--message", default="hello from demo", help="plaintext message")
    args = p.parse_args()

    # prepare message
    plaintext = args.message.encode()
    plaintext_b64 = base64.b64encode(plaintext).decode()

    # call encrypt endpoint on server
    payload = {"level": 2, "recipient_device_id": args.device_id, "plaintext_b64": plaintext_b64}
    r = requests.post(f"{SERVER}/encrypt", json=payload)
    r.raise_for_status()
    enc = r.json()
    print("Server encrypt response:", json.dumps(enc, indent=2))

    # load recipient private key (base64)
    priv_b64 = Path(args.privfile).read_text().strip()
    try:
        priv = base64.b64decode(priv_b64)
    except Exception as e:
        print("ERROR: failed to base64-decode private key file. Make sure it contains only the base64 text.", file=sys.stderr)
        raise

    kem_ct_b64 = enc["kem_ct_b64"]
    ciphertext_b64 = enc["ciphertext_b64"]
    nonce_b64 = enc["nonce_b64"]

    kem_name = "Kyber512"  # adjust if your server uses a different kem

    try:
        ss = try_decap_with_various_signatures(kem_name, priv, base64.b64decode(kem_ct_b64))
    except Exception as e:
        # Print diagnostic info to stderr and re-raise with context
        print("Decapsulation failed. Error:", e, file=sys.stderr)
        print("Attempting to inspect kem object methods for debugging...", file=sys.stderr)
        info = inspect_kem_methods(kem_name)
        print(json.dumps(info, indent=2), file=sys.stderr)
        print("\nPaste the above diagnostics to your developer if you need further assistance.", file=sys.stderr)
        raise

    # derive AES key & decrypt ciphertext
    aes_key = derive_aes_from_ss(ss)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(base64.b64decode(nonce_b64), base64.b64decode(ciphertext_b64), b"qmail-level2")
    print("Decrypted plaintext:", plaintext.decode())

if __name__ == "__main__":
    main()
