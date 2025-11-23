"""
Compose Router - Send emails with multi-level encryption
Now includes group email support with Level 1/2 encryption
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import base64
import os

from database import get_db
from models import User, OAuthToken, Group, GroupMember, Device
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

# PQC imports
try:
    import oqs
    kem = oqs.KeyEncapsulation("Kyber512")
except:
    kem = None

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

router = APIRouter(prefix="/api/compose", tags=["compose"])


# ==================== Request Models ====================

class ComposeEmailRequest(BaseModel):
    to: Optional[str] = None  # Single recipient OR
    group_id: Optional[int] = None  # Group ID
    subject: str
    body: str
    encryption_level: int  # 1 (plain), 2 (Kyber+AES)


# ==================== Helper Functions ====================

def derive_aes_from_ss(shared_secret: bytes) -> bytes:
    """Derive AES-256 key from Kyber shared secret using HKDF"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qmail-aes"
    ).derive(shared_secret)


def encrypt_level2(plaintext: str, recipient_pubkey_b64: str) -> dict:
    """
    Encrypt message with Level 2 (Kyber512 + AES-GCM)
    Returns: {kem_ct_b64, nonce_b64, ciphertext_b64}
    """
    if not kem:
        raise HTTPException(status_code=500, detail="PQC encryption not available")
    
    # Perform KEM encapsulation
    kem_ct_b64, shared_secret_b64 = kem.encapsulate(recipient_pubkey_b64)
    shared_secret = base64.b64decode(shared_secret_b64)
    
    # Derive AES key
    aes_key = derive_aes_from_ss(shared_secret)
    
    # Encrypt plaintext
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, b"qmail-level2")
    
    return {
        "kem_ct_b64": kem_ct_b64,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }


def encrypt_with_group_key(plaintext: str, group_aes_key_b64: str) -> dict:
    """
    Encrypt message with group's shared AES key
    Returns: {nonce_b64, ciphertext_b64}
    """
    group_aes_key = base64.b64decode(group_aes_key_b64)
    
    aesgcm = AESGCM(group_aes_key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, b"qmail-group-level2")
    
    return {
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }


def format_level2_email_body(encrypted_data: dict) -> str:
    """Format Level 2 encrypted email body"""
    return f"""
🔐 This message is encrypted with QMail Level 2 (Quantum-Secure)
To decrypt, please use QMail app: https://qmail-app.com

--- ENCRYPTED PAYLOAD ---
kem_ct_b64: {encrypted_data['kem_ct_b64']}
nonce_b64: {encrypted_data['nonce_b64']}
ciphertext_b64: {encrypted_data['ciphertext_b64']}
--- END ENCRYPTED PAYLOAD ---
"""


def format_group_level2_email_body(group_name: str, group_id: int, encrypted_data: dict) -> str:
    """Format Group Level 2 encrypted email body"""
    return f"""
👥 This is a group message from: {group_name}
🔐 Encrypted with QMail Level 2 (Quantum-Secure)
To decrypt, please use QMail app: https://qmail-app.com

--- GROUP ENCRYPTED PAYLOAD ---
group_id: {group_id}
group_name: {group_name}
nonce_b64: {encrypted_data['nonce_b64']}
ciphertext_b64: {encrypted_data['ciphertext_b64']}
--- END GROUP ENCRYPTED PAYLOAD ---
"""


# ==================== API Endpoints ====================

@router.post("/send")
async def send_email(
    request: ComposeEmailRequest,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token),
    db: Session = Depends(get_db)
):
    """
    Send email with specified encryption level
    Supports both individual and group recipients
    """
    
    # Validate request
    if not request.to and not request.group_id:
        raise HTTPException(
            status_code=400,
            detail="Either 'to' or 'group_id' must be provided"
        )
    
    if request.to and request.group_id:
        raise HTTPException(
            status_code=400,
            detail="Cannot specify both 'to' and 'group_id'"
        )
    
    gmail = GmailService(
        access_token=oauth_token.access_token,
        refresh_token=oauth_token.refresh_token
    )
    
    # ===== GROUP EMAIL =====
    if request.group_id:
        # Verify group membership
        group = db.query(Group).filter(Group.id == request.group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == request.group_id,
            GroupMember.user_id == current_user.id
        ).first()
        
        if not membership:
            raise HTTPException(
                status_code=403,
                detail="You are not a member of this group"
            )
        
        # Get all group members
        members = db.query(GroupMember).filter(
            GroupMember.group_id == request.group_id
        ).all()
        
        member_emails = []
        for member in members:
            user = db.query(User).filter(User.id == member.user_id).first()
            if user:
                member_emails.append(user.email)
        
        if not member_emails:
            raise HTTPException(status_code=400, detail="Group has no members")
        
        # Prepare email based on encryption level
        if request.encryption_level == 1:
            # Plain group email
            final_subject = f"[Group: {group.name}] {request.subject}"
            final_body = request.body
        
        elif request.encryption_level == 2:
            # Encrypted group email
            if not group.aes_key_b64:
                raise HTTPException(
                    status_code=500,
                    detail="Group encryption key not found"
                )
            
            encrypted_data = encrypt_with_group_key(request.body, group.aes_key_b64)
            final_subject = f"[Group: {group.name}] {request.subject}"
            final_body = format_group_level2_email_body(
                group.name,
                group.id,
                encrypted_data
            )
        
        else:
            raise HTTPException(
                status_code=400,
                detail="Only Level 1 and 2 encryption supported for groups"
            )
        
        # Send to all group members
        results = []
        for email in member_emails:
            try:
                result = gmail.send_message(
                    to=email,
                    subject=final_subject,
                    body=final_body
                )
                results.append({
                    "to": email,
                    "success": True,
                    "message_id": result['id']
                })
            except Exception as e:
                results.append({
                    "to": email,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": True,
            "message": f"Group email sent to {len(member_emails)} members",
            "group_id": request.group_id,
            "group_name": group.name,
            "encryption_level": request.encryption_level,
            "results": results
        }
    
    # ===== INDIVIDUAL EMAIL =====
    else:
        # Validate recipient
        recipient_user = db.query(User).filter(User.email == request.to).first()
        
        if request.encryption_level == 1:
            # Plain email
            final_subject = request.subject
            final_body = request.body
        
        elif request.encryption_level == 2:
            # Level 2 encryption
            if not recipient_user:
                raise HTTPException(
                    status_code=400,
                    detail=f"{request.to} is not a QMail user. Cannot use Level 2 encryption."
                )
            
            # Get recipient's most recent device
            recipient_device = db.query(Device).filter(
                Device.user_id == recipient_user.id
            ).order_by(Device.created_at.desc()).first()
            
            if not recipient_device:
                raise HTTPException(
                    status_code=400,
                    detail=f"{request.to} has no registered devices"
                )
            
            encrypted_data = encrypt_level2(request.body, recipient_device.pubkey_b64)
            final_subject = f"🔐 {request.subject}"
            final_body = format_level2_email_body(encrypted_data)
        
        elif request.encryption_level == 3:
            raise HTTPException(
                status_code=400,
                detail="Level 3 encryption not yet implemented in this endpoint"
            )
        
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid encryption level. Must be 1, 2, or 3"
            )
        
        # Send email
        result = gmail.send_message(
            to=request.to,
            subject=final_subject,
            body=final_body
        )
        
        return {
            "success": True,
            "message": "Email sent successfully",
            "message_id": result['id'],
            "to": request.to,
            "encryption_level": request.encryption_level
        }


@router.get("/check-recipient")
async def check_recipient(
    email: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Check if recipient is a QMail user and has devices
    Returns available encryption levels
    """
    
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        return {
            "is_qmail_user": False,
            "has_devices": False,
            "available_levels": [1]  # Only plain email
        }
    
    device_count = db.query(Device).filter(Device.user_id == user.id).count()
    
    if device_count == 0:
        return {
            "is_qmail_user": True,
            "has_devices": False,
            "available_levels": [1]  # Only plain email
        }
    
    return {
        "is_qmail_user": True,
        "has_devices": True,
        "available_levels": [1, 2, 3]  # All levels available
    }


@router.get("/groups/{group_id}/available-levels")
async def get_group_encryption_levels(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get available encryption levels for a group
    Groups support Level 1 and 2 only
    """
    
    # Verify membership
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You are not a member of this group"
        )
    
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if all members have devices
    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
    all_have_devices = True
    
    for member in members:
        device_count = db.query(Device).filter(Device.user_id == member.user_id).count()
        if device_count == 0:
            all_have_devices = False
            break
    
    available_levels = [1]  # Always support Level 1
    if all_have_devices:
        available_levels.append(2)  # Support Level 2 if all have devices
    
    return {
        "group_id": group_id,
        "group_name": group.name,
        "available_levels": available_levels,
        "member_count": len(members)
    }
