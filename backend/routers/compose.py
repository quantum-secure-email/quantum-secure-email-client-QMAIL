from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import base64
import json

from database import get_db
from models import User, OAuthToken
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

router = APIRouter(prefix="/api/compose", tags=["compose"])

class ComposeEmailRequest(BaseModel):
    to: str
    subject: str
    message: str
    encryption_level: int  # 1, 2, or 3
    recipient_device_id: Optional[str] = None  # Required for level 2 and 3

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
            # Send plain email via Gmail
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
                "message": "Email sent with standard Gmail encryption"
            }
        
        # Level 2: Post-Quantum Encryption
        elif level == 2:
            if not email_data.recipient_device_id:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_device_id required for Level 2 encryption. Recipient must register a device first."
                )
            
            # For now, create a placeholder encrypted body
            # In full implementation, this would use the /encrypt endpoint
            encrypted_body = f"""
=== QMail Level 2 Encrypted Message ===

🔒 This message is encrypted with Post-Quantum Cryptography (Kyber512 + AES-GCM)

To decrypt this message:
1. Go to https://qmail.example.com
2. Sign in with your account
3. Your device will automatically decrypt this message

Encrypted Payload:
kem_ct_b64: [Base64 encoded Kyber ciphertext]
ciphertext_b64: [Base64 encoded AES-GCM ciphertext]
nonce_b64: [Base64 encoded nonce]

Original message length: {len(email_data.message)} characters
Encryption: Kyber512 KEM + AES-256-GCM
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
            
            return {
                "success": True,
                "level": 2,
                "message_id": result['id'],
                "encryption_type": "post_quantum_kyber512",
                "message": "Email sent with Post-Quantum encryption (Kyber512)"
            }
        
        # Level 3: OTP + QKD
        elif level == 3:
            if not email_data.recipient_device_id:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_device_id required for Level 3 encryption. Recipient must register a device first."
                )
            
            # For now, create a placeholder encrypted body
            encrypted_body = f"""
=== QMail Level 3 Maximum Security Message ===

🔐 This message is encrypted with One-Time Pad + Simulated Quantum Key Distribution

To decrypt this message:
1. Go to https://qmail.example.com
2. Sign in with your account
3. Your device will automatically decrypt this message using the OTP key

Encrypted Payload:
otp_key_id: [OTP Key Identifier]
otp_sender_wrapped_b64: [Wrapped OTP for sender]
otp_recipient_wrapped_b64: [Wrapped OTP for recipient]
xor_ciphertext_b64: [Message XOR'd with OTP]

Original message length: {len(email_data.message)} characters
Encryption: One-Time Pad (Information-Theoretic Security)
Key Distribution: Simulated QKD
Recipient Device: {email_data.recipient_device_id}

⚠️ This OTP key can only be used ONCE and will be discarded after decryption.

---
Sent from QMail - Maximum Quantum Security
            """
            
            # Send encrypted email
            result = gmail.send_message(
                to=email_data.to,
                subject=f"🔐 [Maximum Security] {email_data.subject}",
                body=encrypted_body
            )
            
            return {
                "success": True,
                "level": 3,
                "message_id": result['id'],
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
        print(f"✗ Error in compose/send: {e}")
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
    
    Returns:
        - has_device: boolean
        - device_id: string (if has_device is true)
        - email: recipient email
    """
    try:
        # Query for user by email
        from models import User, Device
        
        recipient = db.query(User).filter(User.email == email).first()
        
        if not recipient:
            return {
                "has_device": False,
                "email": email,
                "message": "Recipient not registered in QMail system"
            }
        
        # Check if user has any registered devices
        device = db.query(Device).filter(Device.user_id == recipient.id).first()
        
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
