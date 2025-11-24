from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import base64
import json
import os
import uuid
import secrets

from database import get_db
from models import User, OAuthToken, Device, KMStore
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

# Import encryption libraries
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

router = APIRouter(prefix="/api/compose", tags=["compose"])

class ComposeEmailRequest(BaseModel):
    to: str
    subject: str
    message: str
    encryption_level: int  # 1, 2, or 3
    recipient_device_id: Optional[str] = None  # Required for level 2 and 3
    # Attachment fields (Level 1 & 2 only)
    attachment_data: Optional[str] = None  # Base64 encoded file (plain for L1, encrypted for L2)
    attachment_filename: Optional[str] = None
    attachment_mimetype: Optional[str] = None
    attachment_size: Optional[int] = None
    attachment_nonce: Optional[str] = None  # Only for Level 2 encrypted attachments

@router.post("/send")
async def compose_and_send(
    email_data: ComposeEmailRequest,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token),
    db: Session = Depends(get_db)
):
    """
    Compose and send email with specified encryption level
    
    Levels:
    - 1: Standard Gmail (TLS only)
    - 2: Post-Quantum (Kyber512 + AES-GCM)
    - 3: OTP + QKD (Maximum security)
    """
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        level = email_data.encryption_level
        
        # Level 1: Standard Gmail
        if level == 1:
            # Check if attachment is present
            if email_data.attachment_data and email_data.attachment_filename:
                print(f"📎 Sending Level 1 email with attachment: {email_data.attachment_filename}")
                result = gmail.send_message_with_attachment(
                    to=email_data.to,
                    subject=email_data.subject,
                    body=email_data.message,
                    attachment_data=email_data.attachment_data,
                    attachment_filename=email_data.attachment_filename,
                    attachment_mimetype=email_data.attachment_mimetype or 'application/octet-stream'
                )
            else:
                result = gmail.send_message(
                    to=email_data.to,
                    subject=email_data.subject,
                    body=email_data.message
                )
            
            return {
                "success": True,
                "level": 1,
                "message_id": result['id'],
                "encryption_type": "standard_gmail",
                "message": "Email sent with standard Gmail encryption",
                "has_attachment": bool(email_data.attachment_data)
            }
        
        # Level 2: Post-Quantum Encryption (ACTUAL ENCRYPTION)
        elif level == 2:
            if not email_data.recipient_device_id:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_device_id required for Level 2 encryption"
                )
            
            print(f"🔐 Level 2 encryption for {email_data.to}")
            
            # Get recipient's device and public key
            device = db.query(Device).filter(
                Device.device_id == email_data.recipient_device_id
            ).first()
            
            if not device:
                raise HTTPException(
                    status_code=404,
                    detail="Recipient device not found"
                )
            
            print(f"  ✅ Found device: {device.device_id}")
            
            # Perform Kyber512 KEM encapsulation
            with oqs.KeyEncapsulation("Kyber512") as kem:
                # Load recipient's public key
                recipient_pubkey = base64.b64decode(device.pubkey_b64)
                
                # Generate ephemeral key and encapsulate
                kem_ciphertext, shared_secret = kem.encap_secret(recipient_pubkey)
            
            print(f"  ✅ KEM encapsulation successful")
            
            # Derive AES-256 key from shared secret using HKDF
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"qmail-aes"
            ).derive(shared_secret)
            
            # Encrypt message with AES-256-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_key)
            message_bytes = email_data.message.encode('utf-8')
            aes_ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
            
            print(f"  ✅ AES-GCM encryption successful")
            
            # Encode everything to base64
            kem_ct_b64 = base64.b64encode(kem_ciphertext).decode()
            ciphertext_b64 = base64.b64encode(aes_ciphertext).decode()
            nonce_b64 = base64.b64encode(nonce).decode()
            
            # Create properly formatted email body
            header_line = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            encrypted_body = f"""{header_line}
🔐 ENCRYPTED WITH QMAIL
This message can only be read in QMail.
Sign in at: https://qmail-frontend.onrender.com
{header_line}

kem_ct_b64: {kem_ct_b64}
ciphertext_b64: {ciphertext_b64}
nonce_b64: {nonce_b64}

Encryption: Kyber512 + AES-256-GCM
Recipient Device: {email_data.recipient_device_id}

---
Sent from QMail - Quantum-Secure Email
"""
            
            # Send encrypted email
            result = gmail.send_message(
                to=email_data.to,
                subject=f"🔒 [Encrypted] {email_data.subject}",
                body=encrypted_body
            )
            
            print(f"  ✅ Email sent: {result['id']}")
            
            return {
                "success": True,
                "level": 2,
                "message_id": result['id'],
                "encryption_type": "post_quantum_kyber512",
                "message": "Email sent with Post-Quantum encryption (Kyber512)",
                "has_attachment": bool(email_data.attachment_data)
            }
        
        # Level 3: OTP + QKD
        elif level == 3:
            if not email_data.recipient_device_id:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_device_id required for Level 3 encryption"
                )
            
            print(f"🔐 Level 3 (OTP) encryption for {email_data.to}")
            
            # Get recipient's device and public key
            device = db.query(Device).filter(
                Device.device_id == email_data.recipient_device_id
            ).first()
            
            if not device:
                raise HTTPException(
                    status_code=404,
                    detail="Recipient device not found"
                )
            
            print(f"  ✅ Found device: {device.device_id}")
            
            # Generate OTP (same length as message)
            message_bytes = email_data.message.encode('utf-8')
            otp = secrets.token_bytes(len(message_bytes))
            
            print(f"  ✅ Generated OTP: {len(otp)} bytes")
            
            # XOR encrypt message with OTP
            xor_ciphertext = bytes([m ^ o for m, o in zip(message_bytes, otp)])
            
            print(f"  ✅ XOR encryption complete")
            
            # Wrap OTP for recipient using their public key
            recipient_pubkey = base64.b64decode(device.pubkey_b64)
            
            with oqs.KeyEncapsulation("Kyber512") as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(recipient_pubkey)
            
            # Derive AES key from shared secret
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"qmail-otp-wrap"
            ).derive(shared_secret)
            
            # Encrypt OTP with AES-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_key)
            otp_aes_ct = aesgcm.encrypt(nonce, otp, b"otp-wrap")
            
            print(f"  ✅ OTP wrapped for recipient")
            
            # Create wrapped OTP payload
            otp_wrapped = {
                "kem_ct_b64": base64.b64encode(kem_ciphertext).decode(),
                "aes_ct_b64": base64.b64encode(otp_aes_ct).decode(),
                "nonce_b64": base64.b64encode(nonce).decode()
            }
            
            # Generate unique OTP key ID
            otp_key_id = str(uuid.uuid4())
            
            # Store OTP metadata in database
            km_entry = KMStore(
                key_id=otp_key_id,
                key_b64=base64.b64encode(otp).decode(),  # Store actual OTP
                used=False,
                origin="otp-level3",
                meta={
                    "sender_id": current_user.id,
                    "recipient_id": device.user_id,
                    "message_length": len(message_bytes),
                    "encryption_type": "OTP-XOR",
                    "wrapped_otps": [
                        {
                            "device_id": device.device_id,
                            "otp_wrapped_b64": base64.b64encode(
                                json.dumps(otp_wrapped).encode()
                            ).decode()
                        }
                    ]
                }
            )
            
            db.add(km_entry)
            db.commit()
            
            print(f"  ✅ OTP stored in database: {otp_key_id}")
            
            # Create email body
            xor_ciphertext_b64 = base64.b64encode(xor_ciphertext).decode()
            header_line = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            encrypted_body = f"""{header_line}
🛡️ ENCRYPTED WITH QMAIL - MAXIMUM SECURITY
This message uses One-Time Pad encryption.
Can only be read in QMail.
{header_line}

otp_key_id: {otp_key_id}
xor_ciphertext_b64: {xor_ciphertext_b64}

Encryption: One-Time Pad (Information-Theoretic Security)
Key Distribution: Simulated Quantum Key Distribution
Recipient Device: {email_data.recipient_device_id}

⚠️ This OTP key can only be used ONCE and will be discarded after decryption.

---
Sent from QMail - Maximum Quantum Security
"""
            
            # Send encrypted email
            result = gmail.send_message(
                to=email_data.to,
                subject=f"🛡️ [Maximum Security] {email_data.subject}",
                body=encrypted_body
            )
            
            print(f"  ✅ Email sent: {result['id']}")
            
            return {
                "success": True,
                "level": 3,
                "message_id": result['id'],
                "otp_key_id": otp_key_id,
                "encryption_type": "otp_qkd",
                "message": "Email sent with Maximum Security (OTP + QKD)"
            }
        
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid encryption level: {level}. Must be 1, 2, or 3."
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"✖ Error in compose/send: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send email: {str(e)}"
        )


@router.get("/check-recipient/{email}")
async def check_recipient_device(
    email: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Check if recipient has registered a device for encrypted communication
    """
    try:
        # Query for user by email
        recipient = db.query(User).filter(User.email == email).first()
        
        if not recipient:
            return {
                "has_device": False,
                "email": email,
                "message": "Recipient not registered in QMail system"
            }
        
        # Check if user has any registered devices (get most recent)
        device = db.query(Device).filter(
            Device.user_id == recipient.id
        ).order_by(Device.created_at.desc()).first()
        
        if device:
            return {
                "has_device": True,
                "device_id": device.device_id,
                "email": email,
                "user_id": recipient.id,
                "algorithm": device.algo
            }
        else:
            return {
                "has_device": False,
                "email": email,
                "user_id": recipient.id,
                "message": "Recipient is registered but has no encryption device"
            }
            
    except Exception as e:
        print(f"Error checking recipient device: {e}")
        raise HTTPException(status_code=500, detail=str(e))
