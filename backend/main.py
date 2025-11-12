# main.py
# Run with:
# uvicorn main:app --reload --host 0.0.0.0 --port 8000

import os
import json
import uuid
import base64
import requests
import email
import email.policy
from routers import auth, inbox
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ---------- Optional PQC (liboqs) ----------
OQS_AVAILABLE = False
try:
    import oqs  # liboqs-python binding
    OQS_AVAILABLE = True
except Exception:
    oqs = None
    OQS_AVAILABLE = False

class PQCKEM:
    def __init__(self, preferred="Kyber512"):
        if not OQS_AVAILABLE:
            raise RuntimeError("liboqs python binding not available")
        self.preferred = preferred
        # determine available KEMs using available API names
        get_kems = None
        if hasattr(oqs, "get_enabled_kem_mechanisms"):
            get_kems = oqs.get_enabled_kem_mechanisms
        elif hasattr(oqs, "get_enabled_kems"):
            get_kems = oqs.get_enabled_kems
        if get_kems:
            enabled = list(get_kems())
            if preferred in enabled:
                self.kem_name = preferred
            else:
                self.kem_name = enabled[0] if enabled else preferred
        else:
            self.kem_name = preferred

    def generate_keypair(self):
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            pk = kem.generate_keypair()
            try:
                sk = kem.export_secret_key()
            except Exception:
                sk = None
        return {"pub_b64": base64.b64encode(pk).decode(), "priv_b64": base64.b64encode(sk).decode() if sk else None, "algo": self.kem_name}

    def encapsulate(self, peer_pub_b64: str):
        peer = base64.b64decode(peer_pub_b64)
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            # try common binding styles
            try:
                out = kem.encap_secret(peer)
                # some bindings return tuple (ct, ss), some return only ss and require other call
                if isinstance(out, tuple) and len(out) == 2:
                    ct, ss = out
                else:
                    # rare fallback: assume encap_secret returned shared secret and ct produced earlier
                    ss = out
                    ct = b""  # not ideal; real binding should return ct
            except TypeError:
                # try alternative: some bindings have kem.encapsulate? handle gracefully
                raise RuntimeError("encapsulation API shape unexpected for binding")
        return {"ct_b64": base64.b64encode(ct).decode(), "ss_b64": base64.b64encode(ss).decode()}

    def decapsulate(self, priv_b64: str, ct_b64: str):
        priv = base64.b64decode(priv_b64)
        ct = base64.b64decode(ct_b64)
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            try:
                ss = kem.decap_secret(priv, ct)
            except TypeError as e:
                raise RuntimeError(f"decap_secret error: {e}")
        return base64.b64encode(ss).decode()

if OQS_AVAILABLE:
    try:
        kem = PQCKEM(preferred="Kyber512")
    except Exception:
        kem = None
else:
    kem = None

# ---------- Data and simulated KM ----------
DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
KM_FILE = DATA_DIR / "km_store.json"
DEVICES_FILE = DATA_DIR / "devices.json"

NUM_OTP_KEYS = 100
OTP_KEY_SIZE = 1024  # bytes

def load_json(p: Path, default):
    if p.exists():
        return json.loads(p.read_text())
    else:
        return default

def save_json(p: Path, obj):
    p.write_text(json.dumps(obj, indent=2))

# initialize KM if missing
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

# ---------- AES helpers ----------
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
    message_length: int  # bytes

class SendEmailReq(BaseModel):
    access_token: str   # Gmail OAuth2 access token from frontend (short-lived)
    from_email: str
    to_email: str
    subject: Optional[str] = ""
    body: Optional[str] = ""

# ---------- App ----------
app = FastAPI(title="Qmail Backend (PQC-enabled)")

app.include_router(auth.router)
app.include_router(inbox.router)

# CORS: allow your frontend origins (add your production origin later)
FRONTEND_ORIGINS = os.environ.get("FRONTEND_ORIGINS", "http://localhost:8080,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in FRONTEND_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Health / PQC probe ----------
def pqc_available_probe():
    if not OQS_AVAILABLE:
        return {"oqs": False, "detail": "oqs import failed"}
    if hasattr(oqs, "get_enabled_kem_mechanisms"):
        try:
            kems = list(oqs.get_enabled_kem_mechanisms())
            return {"oqs": True, "kem_sample": kems[:8]}
        except Exception as e:
            return {"oqs": False, "detail": f"get_enabled_kem_mechanisms error: {e}"}
    for fn in ("get_enabled_kems", "get_enabled_KEMs"):
        if hasattr(oqs, fn):
            try:
                k = list(getattr(oqs, fn)())
                return {"oqs": True, "kem_sample": k[:8]}
            except Exception as e:
                return {"oqs": False, "detail": f"{fn} error: {e}"}
    if hasattr(oqs, "KeyEncapsulation"):
        try:
            with oqs.KeyEncapsulation("Kyber512") as testkem:
                kem_name = getattr(testkem, "kem_name", None) or getattr(testkem, "name", "Kyber512")
            return {"oqs": True, "kem_algo": kem_name}
        except Exception as e:
            return {"oqs": False, "detail": f"KeyEncapsulation error: {e}"}
    return {"oqs": False, "detail": "oqs present but no usable KEM API found"}

@app.get("/health")
def health():
    return {"ok": True, **pqc_available_probe()}

# ---------- Device endpoints ----------
@app.post("/device/register")
def register_device(req: DeviceRegister):
    devices = get_devices()
    # enforce single pubkey -> one device id
    for did, info in devices.items():
        if info.get("pubkey_b64") == req.pubkey_b64:
            return {"device_id": did, "status": "already_registered", "note": "pubkey already registered"}
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

# ---------- Encrypt endpoints ----------
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
def allocate_otp(req: Dict[str, Any]):
    km = get_km()
    sender_id = req["sender_device_id"]
    recipient_id = req["recipient_device_id"]
    length = int(req.get("message_length", 100))

    # find unused OTP key with enough length
    key_id = None
    key_info = None
    for v in km["keys"]:
        if not v.get("used", False) and len(base64.b64decode(v.get("key_b64", ""))) >= length:
            key_id, key_info = v["id"], v
            break
    if not key_id or key_info is None:
        raise HTTPException(500, "No available OTP keys in KM")

    otp = base64.b64decode(key_info["key_b64"])[:length]
    key_info["used"] = True
    save_km(km)

    def wrap_for_device(device_id: str):
        devices = get_devices()
        dev = devices.get(device_id)
        if not dev:
            raise HTTPException(404, f"Device {device_id} not found")
        pub_b64 = dev["pubkey_b64"]
        if kem is None:
            raise HTTPException(status_code=500, detail="PQC KEM not available on server")
        enc_result = kem.encapsulate(pub_b64)
        kem_ct = base64.b64decode(enc_result["ct_b64"])
        ss = base64.b64decode(enc_result["ss_b64"])
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qmail-otp-wrap").derive(ss)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        aes_ct = aesgcm.encrypt(nonce, otp, b"qmail-otp-wrap")
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

# ---------- Debug endpoints ----------
@app.post("/debug/decrypt-level2")
def debug_decrypt_level2(payload: Dict[str, Any] = Body(...)):
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
def debug_decrypt_otp(payload: Dict[str, Any] = Body(...)):
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

# ---------- Gmail helper endpoints (demo: uses client-side token) ----------
def make_raw_message(from_addr: str, to_addr: str, subject: str, body_text: str) -> str:
    msg = email.message.EmailMessage(policy=email.policy.SMTP)
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body_text)
    raw_bytes = msg.as_bytes()
    raw_b64 = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
    return raw_b64

@app.post("/verify-token")
def verify_token(payload: Dict[str, Any] = Body(...)):
    token = payload.get("access_token")
    if not token:
        raise HTTPException(status_code=400, detail="access_token required")
    r = requests.get("https://www.googleapis.com/oauth2/v3/tokeninfo", params={"access_token": token}, timeout=10)
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail=f"tokeninfo error: {r.text}")
    return {"token_info": r.json()}

@app.post("/send-email")
def send_email(req: SendEmailReq):
    token = req.access_token
    if not token:
        raise HTTPException(status_code=400, detail="access_token required")

    ti = requests.get("https://www.googleapis.com/oauth2/v3/tokeninfo", params={"access_token": token}, timeout=10)
    if ti.status_code != 200:
        raise HTTPException(status_code=401, detail=f"tokeninfo failed: {ti.text}")
    info = ti.json()
    scopes = info.get("scope", "")
    required = {
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    # optional: accept full mailbox scope too
    "https://mail.google.com/"
}
    present = set(scopes.split())  # tokeninfo returns lowercase space-separated list
    if not (present & required):
        raise HTTPException(status_code=403, detail=f"insufficient scopes on token: {scopes}")


    raw_b64 = make_raw_message(req.from_email, req.to_email, req.subject or "", req.body or "")
    gmail_send_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"raw": raw_b64}
    r = requests.post(gmail_send_url, headers=headers, json=payload, timeout=15)
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Gmail API error ({r.status_code}): {r.text}")
    return {"ok": True, "gmail_response": r.json()}

# ---------- End ----------
