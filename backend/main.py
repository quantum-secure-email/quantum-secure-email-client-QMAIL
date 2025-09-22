# main.py
"""
Qmail backend prototype (device-bound encryption).
- Device registration: devices upload public key (PQC/KEM public)
- Level-2: server encapsulates to recipient pubkey -> derives AES-256-GCM key -> encrypts payload
- Level-3 (OTP): KM supplies a random 1KB OTP key but returns it wrapped (encapsulated) to BOTH sender and recipient
  so the raw OTP never leaves KM in plaintext.
- Uses liboqs (oqs) if installed for Kyber KEM; otherwise falls back to X25519-based simulation.
Run:
  pip install -r requirements.txt
  uvicorn main:app --reload --port 8000
"""
import os
import json
import uuid
import base64
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Body, UploadFile, File
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# Try liboqs (Kyber) first
try:
    import oqs
    OQS = True
except Exception:
    OQS = False
    from cryptography.hazmat.primitives.asymmetric import x25519

DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
KM_FILE = DATA_DIR / "km_store.json"
DEVICES_FILE = DATA_DIR / "devices.json"

# Config
NUM_OTP_KEYS = 100
OTP_KEY_SIZE = 1024  # bytes (1KB)
KEM_PREFERRED = "Kyber512"  # will pick available if not present

app = FastAPI(title="Qmail Backend (device-bound encryption)")

# ---------- Persistence helpers ----------
def load_json(p: Path, default):
    if p.exists():
        return json.loads(p.read_text())
    else:
        return default

def save_json(p: Path, obj):
    p.write_text(json.dumps(obj, indent=2))

# Init KM if not present
if not KM_FILE.exists():
    km = {"keys": []}
    for _ in range(NUM_OTP_KEYS):
        kid = str(uuid.uuid4())
        key = os.urandom(OTP_KEY_SIZE)
        km["keys"].append({
            "id": kid,
            "key_b64": base64.b64encode(key).decode(),
            "used": False,
            "origin": "sim-qkd",  # simulated QKD
            "meta": {}
        })
    save_json(KM_FILE, km)

# Init devices store
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

# ---------- KEM wrapper ----------
class KEM:
    def __init__(self):
        self.oqs = OQS
        if self.oqs:
            enabled = oqs.get_enabled_KEMs()
            # pick Kyber variant if available
            if KEM_PREFERRED in enabled:
                self.kem_name = KEM_PREFERRED
            else:
                self.kem_name = enabled[0]
        else:
            self.kem_name = "X25519-sim"

    def generate_keypair(self):
        if self.oqs:
            with oqs.KeyEncapsulation(self.kem_name) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                return {"pub_b64": base64.b64encode(pk).decode(), "priv_b64": base64.b64encode(sk).decode(), "algo": self.kem_name}
        else:
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            sk_raw = sk.private_bytes(encoding=serialization.Encoding.Raw,
                                      format=serialization.PrivateFormat.Raw,
                                      encryption_algorithm=serialization.NoEncryption())
            pk_raw = pk.public_bytes(encoding=serialization.Encoding.Raw,
                                     format=serialization.PublicFormat.Raw)
            return {"pub_b64": base64.b64encode(pk_raw).decode(), "priv_b64": base64.b64encode(sk_raw).decode(), "algo": self.kem_name}

    def encapsulate(self, peer_pub_b64):
        peer = base64.b64decode(peer_pub_b64)
        if self.oqs:
            with oqs.KeyEncapsulation(self.kem_name) as kem:
                ct, ss = kem.encap_secret(peer)
                return {"ct_b64": base64.b64encode(ct).decode(), "ss_b64": base64.b64encode(ss).decode()}
        else:
            # X25519 simulation: ephemeral X25519 generate
            eph = x25519.X25519PrivateKey.generate()
            eph_pub = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                   format=serialization.PublicFormat.Raw)
            peer_obj = x25519.X25519PublicKey.from_public_bytes(peer)
            shared = eph.exchange(peer_obj)
            ss = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-kem").derive(shared)
            return {"ct_b64": base64.b64encode(eph_pub).decode(), "ss_b64": base64.b64encode(ss).decode()}

    def decapsulate(self, priv_b64, ct_b64):
        priv = base64.b64decode(priv_b64)
        ct = base64.b64decode(ct_b64)
        if self.oqs:
            with oqs.KeyEncapsulation(self.kem_name) as kem:
                ss = kem.decap_secret(priv, ct)
                return base64.b64encode(ss).decode()
        else:
            priv_obj = x25519.X25519PrivateKey.from_private_bytes(priv)
            shared = priv_obj.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
            ss = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-kem").derive(shared)
            return base64.b64encode(ss).decode()

kem = KEM()

# ---------- AES-GCM helpers ----------
def derive_aes_from_ss(ss_bytes: bytes) -> bytes:
    # Derive 32-byte AES key
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

# ---------- OTP helpers ----------
def otp_xor(key_bytes: bytes, data: bytes) -> bytes:
    if len(data) > len(key_bytes):
        raise ValueError("OTP: data larger than key")
    return bytes([data[i] ^ key_bytes[i] for i in range(len(data))])

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

# ---------- Endpoints ----------
@app.get("/health")
def health():
    return {"ok": True, "oqs": OQS, "kem_algo": kem.kem_name}

@app.post("/device/register")
def register_device(req: DeviceRegister):
    devices = get_devices()
    did = req.device_id or str(uuid.uuid4())
    devices[did] = {"pubkey_b64": req.pubkey_b64, "algo": req.algo or kem.kem_name, "meta": req.meta}
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

@app.post("/encrypt")  # level 1/2/3 handler; level2 uses server encapsulation
def encrypt(req: EncryptReq):
    if req.level == 1:
        return {"level": 1, "payload_b64": req.plaintext_b64}
    elif req.level == 2:
        # server encapsulates to recipient device pubkey, encrypts with AES-GCM
        if not req.recipient_device_id:
            raise HTTPException(status_code=400, detail="recipient_device_id required for level 2")
        devices = get_devices()
        rec = devices.get(req.recipient_device_id)
        if not rec:
            raise HTTPException(status_code=404, detail="recipient device not found")
        if not req.plaintext_b64:
            raise HTTPException(status_code=400, detail="plaintext_b64 required")
        enc = kem.encapsulate(rec["pubkey_b64"])
        ss = base64.b64decode(enc["ss_b64"])
        aes_key = derive_aes_from_ss(ss)
        plaintext = base64.b64decode(req.plaintext_b64)
        ctobj = aes_encrypt(aes_key, plaintext, aad=b"qmail-level2")
        # return ciphertext and KEM capsule (recipient will decapsulate locally)
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
def allocate_otp(req: AllocateOTPReq):
    # Safety: ensure message length <= OTP_KEY_SIZE
    if req.message_length > OTP_KEY_SIZE:
        raise HTTPException(status_code=400, detail=f"message too big for OTP ({OTP_KEY_SIZE} bytes max)")
    devices = get_devices()
    sender = devices.get(req.sender_device_id)
    rec = devices.get(req.recipient_device_id)
    if not sender or not rec:
        raise HTTPException(status_code=404, detail="sender or recipient device not registered")
    # find unused OTP key
    km = get_km()
    unused = next((k for k in km["keys"] if not k["used"]), None)
    if not unused:
        raise HTTPException(status_code=500, detail="no OTP keys left")
    # Mark used in KM (single-use)
    unused["used"] = True
    save_km(km)
    raw_key = base64.b64decode(unused["key_b64"])
    # Instead of returning raw key, wrap (encapsulate) to both sender and recipient
    wrap_sender = kem.encapsulate(sender["pubkey_b64"])
    ss_sender = base64.b64decode(wrap_sender["ss_b64"])
    # derive short symmetric key to encrypt raw_key for sender (we encrypt raw_key with AES derived)
    aes_for_sender = derive_aes_from_ss(ss_sender)
    # encrypt raw_key with AES-GCM for sender (so only sender can decapsulate and decrypt to obtain raw OTP)
    sender_wrap = aes_encrypt(aes_for_sender, raw_key, aad=b"qmail-otp-wrap")

    wrap_rec = kem.encapsulate(rec["pubkey_b64"])
    ss_rec = base64.b64decode(wrap_rec["ss_b64"])
    aes_for_rec = derive_aes_from_ss(ss_rec)
    rec_wrap = aes_encrypt(aes_for_rec, raw_key, aad=b"qmail-otp-wrap")

    # Return the following: the km_key_id (for audit), and two wrapped payloads (sender, recipient).
    return {
        "km_key_id": unused["id"],
        "wrapped_for_sender": {
            "kem_ct_b64": wrap_sender["ct_b64"],
            "aes_ct_b64": sender_wrap["ct_b64"],
            "nonce_b64": sender_wrap["nonce_b64"]
        },
        "wrapped_for_recipient": {
            "kem_ct_b64": wrap_rec["ct_b64"],
            "aes_ct_b64": rec_wrap["ct_b64"],
            "nonce_b64": rec_wrap["nonce_b64"]
        },
        "note": "Both parties must decapsulate kem_ct with their private key, derive AES key from shared secret, and decrypt aes_ct to obtain OTP key bytes."
    }

@app.post("/debug/decrypt-level2")  # debugging only
def debug_decrypt_level2(payload: dict = Body(...)):
    """
    Debug helper: Accepts recipient_priv_b64, kem_ct_b64, nonce_b64, ciphertext_b64
    Returns plaintext_b64. ONLY FOR LOCAL TESTING.
    """
    required = ["recipient_priv_b64", "kem_ct_b64", "nonce_b64", "ciphertext_b64"]
    if not all(k in payload for k in required):
        raise HTTPException(status_code=400, detail=f"required fields: {required}")
    ss_b64 = kem.decapsulate(payload["recipient_priv_b64"], payload["kem_ct_b64"])
    ss = base64.b64decode(ss_b64)
    aes_key = derive_aes_from_ss(ss)
    pt = aes_decrypt(aes_key, payload["nonce_b64"], payload["ciphertext_b64"], aad=b"qmail-level2")
    return {"plaintext_b64": base64.b64encode(pt).decode()}

@app.post("/debug/decrypt-otp")  # debugging only
def debug_decrypt_otp(payload: dict = Body(...)):
    """
    Debug helper: Accepts recipient_priv_b64, kem_ct_b64, nonce_b64, aes_ct_b64
    Decrypts wrapped OTP to raw key and returns it (base64). ONLY FOR LOCAL TESTING.
    """
    required = ["recipient_priv_b64", "kem_ct_b64", "nonce_b64", "aes_ct_b64"]
    if not all(k in payload for k in required):
        raise HTTPException(status_code=400, detail=f"required fields: {required}")
    ss_b64 = kem.decapsulate(payload["recipient_priv_b64"], payload["kem_ct_b64"])
    ss = base64.b64decode(ss_b64)
    aes_key = derive_aes_from_ss(ss)
    key_bytes = aes_decrypt(aes_key, payload["nonce_b64"], payload["aes_ct_b64"], aad=b"qmail-otp-wrap")
    return {"raw_key_b64": base64.b64encode(key_bytes).decode()}
