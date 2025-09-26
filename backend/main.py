# main.py
# uvicorn main:app --reload --host 0.0.0.0 --port 8000


import os
import json
import uuid
import base64
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ---------- Attempt to import oqs and prepare a KEM wrapper ----------
OQS_AVAILABLE = False
try:
    import oqs  # liboqs-python binding
    OQS_AVAILABLE = True
except Exception:
    oqs = None
    OQS_AVAILABLE = False

# Provide a thin wrapper around KEM operations that uses oqs.KeyEncapsulation
class PQCKEM:
    def __init__(self, preferred="Kyber512"):
        if not OQS_AVAILABLE:
            raise RuntimeError("liboqs python binding not available")
        # Try to pick a reasonable KEM name if preferred not available
        self.preferred = preferred
        # Determine enabled KEMs using modern API
        get_kems = None
        if hasattr(oqs, "get_enabled_kem_mechanisms"):
            get_kems = oqs.get_enabled_kem_mechanisms # type: ignore
        elif hasattr(oqs, "get_enabled_kems"):
            get_kems = oqs.get_enabled_kems # type: ignore
        if get_kems:
            enabled = list(get_kems())
            if preferred in enabled:
                self.kem_name = preferred
            else:
                # fallback to the first enabled KEM (should include Kyber variants)
                self.kem_name = enabled[0] if enabled else preferred
        else:
            self.kem_name = preferred

    def generate_keypair(self):
        # Note: some oqs bindings provide export_secret_key; binding semantics vary.
        with oqs.KeyEncapsulation(self.kem_name) as kem: # type: ignore
            pk = kem.generate_keypair()
            try:
                sk = kem.export_secret_key()
            except Exception:
                sk = None
        return {"pub_b64": base64.b64encode(pk).decode(), "priv_b64": base64.b64encode(sk).decode() if sk else None, "algo": self.kem_name}

    def encapsulate(self, peer_pub_b64: str):
        peer = base64.b64decode(peer_pub_b64)
        with oqs.KeyEncapsulation(self.kem_name) as kem:# type: ignore
            # Python binding: kem.encap_secret(peer_pub) -> returns (ct, ss) or kem.encap_secret(peer) depending on version
            # We'll try common forms:
            try:
                ct, ss = kem.encap_secret(peer)
            except TypeError:
                # some bindings return ss only and produce ct via kem.generate_keypair? fallback attempt:
                ct = kem.generate_keypair()
                ss = kem.encap_secret(peer)
            return {"ct_b64": base64.b64encode(ct).decode(), "ss_b64": base64.b64encode(ss).decode()} # type: ignore

    def decapsulate(self, priv_b64: str, ct_b64: str):
        priv = base64.b64decode(priv_b64)
        ct = base64.b64decode(ct_b64)
        with oqs.KeyEncapsulation(self.kem_name) as kem: # type: ignore
            try:
                ss = kem.decap_secret(priv, ct) # type: ignore
            except TypeError as e:
                # Some binding shapes may differ; re-raise with context
                raise RuntimeError(f"decap_secret error: {e}")
        return base64.b64encode(ss).decode()

# If QPC available, instantiate wrapper
if OQS_AVAILABLE:
    try:
        kem = PQCKEM(preferred="Kyber512")
    except Exception:
        kem = None
else:
    kem = None

# ---------- Data and KM (simulated) ----------
DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
KM_FILE = DATA_DIR / "km_store.json"
DEVICES_FILE = DATA_DIR / "devices.json"

NUM_OTP_KEYS = 100
OTP_KEY_SIZE = 1024  # 1KB per OTP key

def load_json(p: Path, default):
    if p.exists():
        return json.loads(p.read_text())
    else:
        return default

def save_json(p: Path, obj):
    p.write_text(json.dumps(obj, indent=2))

# initialize KM (simulated QKD origin)
if not KM_FILE.exists():
    km = {"keys": []}
    for _ in range(NUM_OTP_KEYS):
        kid = str(uuid.uuid4())
        raw = os.urandom(OTP_KEY_SIZE)
        km["keys"].append({
            "id": kid,
            "key_b64": base64.b64encode(raw).decode(),
            "used": False,
            "origin": "sim-qkd",
            "meta": {}
        })
    save_json(KM_FILE, km)

if not DEVICES_FILE.exists():
    save_json(DEVICES_FILE, {})

def get_km():
    return load_json(KM_FILE, {"keys": []})

def save_km(km):
    save_json(KM_FILE, km)

def get_devices():
    return load_json(DEVICES_FILE, {})

def save_devices(dev):
    save_json(DEVICES_FILE, dev)

# ---------- AES-GCM helpers ----------
def derive_aes_from_ss(ss_bytes: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-aes").derive(ss_bytes)

def aes_encrypt(aes_key: bytes, plaintext: bytes, aad: Optional[bytes] = None):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {"nonce_b64": base64.b64encode(nonce).decode(), "ct_b64": base64.b64encode(ct).decode()}

def aes_decrypt(aes_key: bytes, nonce_b64: str, ct_b64: str, aad: Optional[bytes] = None):
    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return aesgcm.decrypt(nonce, ct, aad)

# ---------- API models ----------
class DeviceRegister(BaseModel):
    device_id: Optional[str] = None
    pubkey_b64: str
    algo: Optional[str] = None
    meta: Optional[dict] = {}

class EncryptReq(BaseModel):
    level: int
    recipient_device_id: Optional[str] = None
    plaintext_b64: Optional[str] = None

class AllocateOTPReq(BaseModel):
    sender_device_id: str
    recipient_device_id: str
    message_length: int  # bytes (must be <= OTP_KEY_SIZE)

# ---------- App & health ----------
app = FastAPI(title="Qmail Backend (PQC-enabled)")

def pqc_available_probe():
    if not OQS_AVAILABLE:
        return {"oqs": False, "detail": "oqs import failed"}
    # try modern API
    if hasattr(oqs, "get_enabled_kem_mechanisms"):
        try:
            kems = list(oqs.get_enabled_kem_mechanisms()) # type: ignore
            return {"oqs": True, "kem_sample": kems[:8]}
        except Exception as e:
            return {"oqs": False, "detail": f"get_enabled_kem_mechanisms error: {e}"}
    # fallback names
    for fn in ("get_enabled_kems", "get_enabled_KEMs"):
        if hasattr(oqs, fn):
            try:
                k = list(getattr(oqs, fn)())
                return {"oqs": True, "kem_sample": k[:8]}
            except Exception as e:
                return {"oqs": False, "detail": f"{fn} error: {e}"}
    # last resort attempt to instantiate
    if hasattr(oqs, "KeyEncapsulation"):
        try:
            with oqs.KeyEncapsulation("Kyber512") as testkem: # type: ignore
                kem_name = getattr(testkem, "kem_name", None) or getattr(testkem, "name", "Kyber512")
            return {"oqs": True, "kem_algo": kem_name}
        except Exception as e:
            return {"oqs": False, "detail": f"KeyEncapsulation error: {e}"}
    return {"oqs": False, "detail": "oqs present but no usable KEM API found"}

@app.get("/health")
def health():
    return {"ok": True, **pqc_available_probe()}

# ---------- Endpoints ----------
# Replace the existing register_device function in main.py with this one.

@app.post("/device/register")
def register_device(req: DeviceRegister):
    devices = get_devices()

    # First, check if pubkey already registered (enforce one device per pubkey)
    for did, info in devices.items():
        if info.get("pubkey_b64") == req.pubkey_b64:
            # Already registered; return existing device id (idempotent)
            return {"device_id": did, "status": "already_registered", "note": "pubkey already registered"}

    # Not found -> create new device_id and register
    did = req.device_id or str(uuid.uuid4())
    devices[did] = {"pubkey_b64": req.pubkey_b64, "algo": req.algo or (kem.kem_name if kem else "unknown"), "meta": req.meta}
    save_devices(devices)
    return {"device_id": did, "status": "registered"}


@app.get("/device/{device_id}")
def get_device(device_id: str):
    devices = get_devices()
    d = devices.get(device_id)
    if not d:
        raise HTTPException(status_code=404, detail="device not found")
    return {"device_id": device_id, **d}

@app.get("/device/pubkey/{device_id}")
def device_pubkey(device_id: str):
    d = get_devices().get(device_id)
    if not d:
        raise HTTPException(status_code=404, detail="device not found")
    return {"device_id": device_id, "pubkey_b64": d["pubkey_b64"], "algo": d.get("algo")}

@app.post("/encrypt")
def encrypt(req: EncryptReq):
    if req.level == 1:
        return {"level": 1, "payload_b64": req.plaintext_b64}
    elif req.level == 2:
        if not req.recipient_device_id:
            raise HTTPException(status_code=400, detail="recipient_device_id required for level 2")
        devices = get_devices()
        rec = devices.get(req.recipient_device_id)
        if not rec:
            raise HTTPException(status_code=404, detail="recipient device not found")
        if not req.plaintext_b64:
            raise HTTPException(status_code=400, detail="plaintext_b64 required")
        if not kem:
            raise HTTPException(status_code=500, detail="PQC KEM not available on server")
        enc = kem.encapsulate(rec["pubkey_b64"])
        ss = base64.b64decode(enc["ss_b64"])
        aes_key = derive_aes_from_ss(ss)
        plaintext = base64.b64decode(req.plaintext_b64)
        ctobj = aes_encrypt(aes_key, plaintext, aad=b"qmail-level2")
        return {
            "level": 2,
            "kem_ct_b64": enc["ct_b64"],
            "ciphertext_b64": ctobj["ct_b64"],
            "nonce_b64": ctobj["nonce_b64"],
            "note": "Recipient device must decapsulate kem_ct with its private key to derive AES key for decryption."
        }
    elif req.level == 3:
        raise HTTPException(status_code=400, detail="Use /allocate-otp to allocate and wrap OTP keys for level 3")
    else:
        raise HTTPException(status_code=400, detail="unknown level")

@app.post("/allocate-otp")
def allocate_otp(req: dict):
    """
    Allocate an unused OTP key from KM and wrap it separately for sender and recipient.
    Uses PQC (Kyber512) to securely wrap OTP bytes.
    """
    km = get_km()
    sender_id = req["sender_device_id"]
    recipient_id = req["recipient_device_id"]
    length = int(req.get("message_length", 100))

    # find an unused OTP key
    key_id, key_info = None, None
    for v in km["keys"]:
        if not v.get("used", False) and len(base64.b64decode(v.get("key_b64", ""))) >= length:
            key_id, key_info = v["id"], v
            break
    if not key_id:
        raise HTTPException(500, "No available OTP keys in KM")

    if key_info is None:
        raise HTTPException(500, "No available OTP keys in KM (key_info is None)")
    otp = base64.b64decode(key_info["key_b64"])[:length]

    # mark as used
    key_info["used"] = True
    save_km(km)

    # helper to wrap OTP for a given device
    def wrap_for_device(device_id: str):
        devices = get_devices()
        dev = devices.get(device_id)
        if not dev:
            raise HTTPException(404, f"Device {device_id} not found")

        pub_b64 = dev["pubkey_b64"]
        kem_name = dev.get("algo", "Kyber512")
        if kem is None:
            raise HTTPException(status_code=500, detail="PQC KEM not available on server")
        enc_result = kem.encapsulate(pub_b64)
        kem_ct = base64.b64decode(enc_result["ct_b64"])
        ss = base64.b64decode(enc_result["ss_b64"])

        # derive AES key with correct HKDF info
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qmail-otp-wrap"
        ).derive(ss)

        # encrypt OTP with AES-GCM (AAD must match client)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        aes_ct = aesgcm.encrypt(nonce, otp, b"qmail-otp-wrap")

        # debug log for cross-check
        print(f"[DEBUG] wrap_for_device {device_id}: kem={kem_name}, "
              f"AES key preview={base64.b64encode(aes_key[:8]).decode()}")

        return {
            "kem_ct_b64": base64.b64encode(kem_ct).decode(),
            "aes_ct_b64": base64.b64encode(aes_ct).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
        }

    return {
        "km_key_id": key_id,
        "wrapped_for_sender": wrap_for_device(sender_id),
        "wrapped_for_recipient": wrap_for_device(recipient_id),
        "note": "Use your device private key to decapsulate and unwrap OTP locally."
    }


# ---------- Debug endpoints (development only) ----------
@app.post("/debug/decrypt-level2")
def debug_decrypt_level2(payload: dict = Body(...)):
    required = ["recipient_priv_b64", "kem_ct_b64", "nonce_b64", "ciphertext_b64"]
    if not all(k in payload for k in required):
        raise HTTPException(status_code=400, detail=f"required fields: {required}")
    if not kem:
        raise HTTPException(status_code=500, detail="PQC KEM not available")
    ss_b64 = kem.decapsulate(payload["recipient_priv_b64"], payload["kem_ct_b64"])
    ss = base64.b64decode(ss_b64)
    aes_key = derive_aes_from_ss(ss)
    pt = aes_decrypt(aes_key, payload["nonce_b64"], payload["ciphertext_b64"], aad=b"qmail-level2")
    return {"plaintext_b64": base64.b64encode(pt).decode()}

@app.post("/debug/decrypt-otp")
def debug_decrypt_otp(payload: dict = Body(...)):
    required = ["recipient_priv_b64", "kem_ct_b64", "nonce_b64", "aes_ct_b64"]
    if not all(k in payload for k in required):
        raise HTTPException(status_code=400, detail=f"required fields: {required}")
    if not kem:
        raise HTTPException(status_code=500, detail="PQC KEM not available")
    ss_b64 = kem.decapsulate(payload["recipient_priv_b64"], payload["kem_ct_b64"])
    ss = base64.b64decode(ss_b64)
    aes_key = derive_aes_from_ss(ss)
    key_bytes = aes_decrypt(aes_key, payload["nonce_b64"], payload["aes_ct_b64"], aad=b"qmail-otp-wrap")
    return {"raw_key_b64": base64.b64encode(key_bytes).decode()}
