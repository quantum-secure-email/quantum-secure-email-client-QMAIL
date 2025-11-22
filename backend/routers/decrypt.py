"""
Backend Decryption Endpoints
Handles KEM decapsulation and OTP unwrapping
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
import base64
import oqs
import json

from database import get_db
from models import User, KMStore
from dependencies import get_current_user

router = APIRouter(prefix="/api/decrypt", tags=["decryption"])


# === Pydantic Models ===

class DecryptLevel2Request(BaseModel):
    kem_ct_b64: str
    private_key_b64: str

class DecryptLevel3Request(BaseModel):
    otp_key_id: str
    device_id: str
    private_key_b64: str


# === Routes ===

@router.post("/level2")
async def decrypt_level2(
    request: DecryptLevel2Request,
    current_user: User = Depends(get_current_user)
):
    """Perform KEM decapsulation for Level 2 decryption"""
    try:
        print(f"🔓 Decrypting for: {current_user.email}")
        print(f"  📦 KEM CT length: {len(request.kem_ct_b64)}")
        print(f"  🔑 Private key length: {len(request.private_key_b64)}")
        
        # Decode from base64
        private_key = base64.b64decode(request.private_key_b64)
        kem_ct = base64.b64decode(request.kem_ct_b64)
        
        print(f"  📦 Decoded KEM CT: {len(kem_ct)} bytes")
        print(f"  🔑 Decoded private key: {len(private_key)} bytes")
        
        # Perform KEM decapsulation with Kyber512
        kem = oqs.KeyEncapsulation("Kyber512")
        
        try:
            # Set the secret key directly (avoid context manager issue)
            kem.secret_key = private_key
            
            # Perform decapsulation
            shared_secret = kem.decap_secret(kem_ct)
            
            print(f"  ✅ Decapsulation successful!")
            print(f"  🔐 Shared secret length: {len(shared_secret)} bytes")
            
            # Encode shared secret to base64
            shared_secret_b64 = base64.b64encode(shared_secret).decode()
            
            return {
                "shared_secret_b64": shared_secret_b64
            }
            
        finally:
            # Prevent cleanup issues
            kem.secret_key = None
    
    except Exception as e:
        print(f"❌ Decapsulation failed!")
        print(f"❌ Error type: {type(e).__name__}")
        print(f"❌ Error message: {str(e)}")
        import traceback
        traceback.print_exc()
        
        raise HTTPException(
            status_code=500,
            detail=f"Decapsulation failed: {str(e)}"
        )


@router.post("/level3")
async def decrypt_level3(
    request: DecryptLevel3Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Decrypt Level 3 email - Unwrap OTP and return it"""
    try:
        print(f"🔓 Level 3 decryption for: {current_user.email}")
        print(f"  🔑 OTP Key ID: {request.otp_key_id}")
        print(f"  📱 Device ID: {request.device_id}")
        
        # Look up OTP key
        otp_key = db.query(KMStore).filter(
            KMStore.key_id == request.otp_key_id
        ).first()
        
        if not otp_key:
            print(f"  ❌ OTP key not found in database")
            raise HTTPException(
                status_code=404,
                detail="OTP key not found"
            )
        
        print(f"  ✓ Found OTP key in database")
        print(f"  📊 OTP meta: {otp_key.meta}")
        
        # Get wrapped OTP for this device
        if not otp_key.meta:
            print(f"  ❌ No meta field in OTP key")
            raise HTTPException(
                status_code=404,
                detail="OTP key has no metadata"
            )
        
        if "wrapped_otps" not in otp_key.meta:
            print(f"  ❌ No wrapped_otps in meta")
            print(f"  📊 Available meta keys: {list(otp_key.meta.keys())}")
            raise HTTPException(
                status_code=404,
                detail="Wrapped OTP not found in metadata"
            )
        
        wrapped_otps = otp_key.meta["wrapped_otps"]
        print(f"  ✓ Found {len(wrapped_otps)} wrapped OTP(s)")
        
        # Find wrapped OTP for this device
        device_wrapped = None
        for idx, wrapped in enumerate(wrapped_otps):
            print(f"    [{idx}] Device: {wrapped.get('device_id')}")
            if wrapped.get("device_id") == request.device_id:
                device_wrapped = wrapped.get("otp_wrapped_b64")
                print(f"  ✓ Found matching wrapped OTP for device")
                break
        
        if not device_wrapped:
            print(f"  ❌ No wrapped OTP found for device: {request.device_id}")
            raise HTTPException(
                status_code=404,
                detail=f"No wrapped OTP found for device {request.device_id}"
            )
        
        print(f"  ✓ Found wrapped OTP for device")
        print(f"  📦 Wrapped OTP length: {len(device_wrapped)}")
        
        # Unwrap OTP
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        # Decode wrapped OTP
        wrapped_json = base64.b64decode(device_wrapped).decode()
        wrapped = json.loads(wrapped_json)
        
        print(f"  ✓ Parsed wrapped OTP JSON")
        
        kem_ct = base64.b64decode(wrapped["kem_ct_b64"])
        aes_ct = base64.b64decode(wrapped["aes_ct_b64"])
        nonce = base64.b64decode(wrapped["nonce_b64"])
        
        print(f"  📊 KEM CT: {len(kem_ct)} bytes")
        print(f"  📊 AES CT: {len(aes_ct)} bytes")
        print(f"  📊 Nonce: {len(nonce)} bytes")
        
        # Decode private key
        private_key = base64.b64decode(request.private_key_b64)
        
        # Decapsulate KEM to get shared secret
        print(f"  🔓 Decapsulating KEM...")
        kem = oqs.KeyEncapsulation("Kyber512")
        try:
            kem.secret_key = private_key
            shared_secret = kem.decap_secret(kem_ct)
            print(f"  ✓ KEM decapsulation successful")
        finally:
            kem.secret_key = None
        
        # Derive AES key
        print(f"  🔑 Deriving AES key...")
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qmail-otp-wrap"
        ).derive(shared_secret)
        
        print(f"  ✓ AES key derived")
        
        # Decrypt OTP
        print(f"  🔓 Decrypting OTP...")
        aesgcm = AESGCM(aes_key)
        otp = aesgcm.decrypt(nonce, aes_ct, b"otp-wrap")
        
        print(f"  ✓ OTP unwrapped successfully")
        print(f"  🔐 OTP length: {len(otp)} bytes")
        
        # Mark OTP as used
        otp_key.used = True
        db.commit()
        print(f"  ✓ Marked OTP as used")
        
        # Return OTP as base64
        otp_b64 = base64.b64encode(otp).decode()
        
        return {
            "otp_b64": otp_b64
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Level 3 decryption failed!")
        print(f"❌ Error type: {type(e).__name__}")
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Level 3 decryption failed: {str(e)}"
        )