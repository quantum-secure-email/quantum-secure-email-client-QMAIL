from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
import base64
import json
import os
import secrets

from database import get_db
from models import User, OAuthToken, Device, Group, GroupMember, GroupKey
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

# Import encryption libraries
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

router = APIRouter(prefix="/api/groups", tags=["groups"])

# ========== Pydantic Models ==========

class CreateGroupRequest(BaseModel):
    name: str

class AddMemberRequest(BaseModel):
    email: str

class SendGroupMessageRequest(BaseModel):
    subject: str
    message: str

class GroupResponse(BaseModel):
    id: int
    name: str
    created_by: int
    member_count: int
    is_creator: bool

class GroupDetailResponse(BaseModel):
    id: int
    name: str
    created_by: int
    is_creator: bool
    members: List[dict]

# ========== Helper Functions ==========

def generate_group_aes_key() -> bytes:
    """Generate a random AES-256 key for group encryption"""
    return secrets.token_bytes(32)

def encrypt_group_key_for_user(group_aes_key: bytes, user_pubkey_b64: str) -> dict:
    """Encrypt group AES key using user's Kyber512 public key"""
    with oqs.KeyEncapsulation("Kyber512") as kem:
        recipient_pubkey = base64.b64decode(user_pubkey_b64)
        kem_ciphertext, shared_secret = kem.encap_secret(recipient_pubkey)
    
    # Derive wrapping key from shared secret
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qmail-group-key"
    ).derive(shared_secret)
    
    # Encrypt group key with wrapping key
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrap_key)
    wrapped_key = aesgcm.encrypt(nonce, group_aes_key, b"group-key-wrap")
    
    return {
        "kem_ct_b64": base64.b64encode(kem_ciphertext).decode(),
        "wrapped_key_b64": base64.b64encode(wrapped_key).decode(),
        "nonce_b64": base64.b64encode(nonce).decode()
    }

# ========== API Endpoints ==========

@router.post("/create")
async def create_group(
    group_data: CreateGroupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new group and generate AES key for encryption"""
    try:
        # Create group
        new_group = Group(
            name=group_data.name,
            created_by=current_user.id
        )
        db.add(new_group)
        db.flush()  # Get group ID
        
        # Add creator as first member
        group_member = GroupMember(
            group_id=new_group.id,
            user_id=current_user.id
        )
        db.add(group_member)
        
        # Generate group AES key
        group_aes_key = generate_group_aes_key()
        
        # Get creator's most recent device
        creator_device = db.query(Device).filter(
            Device.user_id == current_user.id
        ).order_by(Device.created_at.desc()).first()
        
        if not creator_device:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="You must register a device before creating a group"
            )
        
        # Encrypt group key for creator
        encrypted_key_data = encrypt_group_key_for_user(
            group_aes_key,
            creator_device.pubkey_b64
        )
        
        # Store encrypted group key for creator
        group_key = GroupKey(
            group_id=new_group.id,
            user_id=current_user.id,
            encrypted_group_key=json.dumps(encrypted_key_data),
            algorithm="Kyber512+AES256"
        )
        db.add(group_key)
        
        db.commit()
        
        return {
            "success": True,
            "group_id": new_group.id,
            "name": new_group.name,
            "message": "Group created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error creating group: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create group: {str(e)}")


@router.get("/list")
async def list_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all groups the current user is a member of"""
    try:
        # Get all groups where user is a member
        memberships = db.query(GroupMember).filter(
            GroupMember.user_id == current_user.id
        ).all()
        
        groups_response = []
        for membership in memberships:
            group = db.query(Group).filter(Group.id == membership.group_id).first()
            if group:
                member_count = db.query(GroupMember).filter(
                    GroupMember.group_id == group.id
                ).count()
                
                groups_response.append({
                    "id": group.id,
                    "name": group.name,
                    "created_by": group.created_by,
                    "member_count": member_count,
                    "is_creator": group.created_by == current_user.id
                })
        
        return {"groups": groups_response}
        
    except Exception as e:
        print(f"Error listing groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{group_id}")
async def get_group_details(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific group"""
    try:
        # Check if user is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == current_user.id
        ).first()
        
        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
        
        # Get group details
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Get all members
        members = db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
        members_data = []
        
        for member in members:
            user = db.query(User).filter(User.id == member.user_id).first()
            if user:
                members_data.append({
                    "user_id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "joined_at": member.joined_at.isoformat() if member.joined_at else None,
                    "is_creator": user.id == group.created_by
                })
        
        return {
            "id": group.id,
            "name": group.name,
            "created_by": group.created_by,
            "is_creator": group.created_by == current_user.id,
            "members": members_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting group details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{group_id}/members/add")
async def add_member(
    group_id: int,
    member_data: AddMemberRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add a new member to the group (creator only)"""
    try:
        # Check if user is the creator
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        if group.created_by != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="Only the group creator can add members"
            )
        
        # Find user by email
        new_member_user = db.query(User).filter(User.email == member_data.email).first()
        if not new_member_user:
            raise HTTPException(
                status_code=404,
                detail=f"User with email {member_data.email} not found"
            )
        
        # Check if already a member
        existing = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == new_member_user.id
        ).first()
        
        if existing:
            raise HTTPException(status_code=400, detail="User is already a member")
        
        # Get new member's most recent device
        member_device = db.query(Device).filter(
            Device.user_id == new_member_user.id
        ).order_by(Device.created_at.desc()).first()
        
        if not member_device:
            raise HTTPException(
                status_code=400,
                detail=f"User {member_data.email} must register a device first"
            )
        
        # Get the group's AES key (decrypt from creator's encrypted key)
        # For simplicity, we'll regenerate and re-encrypt for all members
        # In production, you'd decrypt the existing key
        
        # Get existing group key entry
        existing_key = db.query(GroupKey).filter(
            GroupKey.group_id == group_id
        ).first()
        
        if not existing_key:
            raise HTTPException(status_code=500, detail="Group key not found")
        
        # For now, we need to regenerate the key and re-encrypt for all members
        # This is a key rotation on member addition
        group_aes_key = generate_group_aes_key()
        
        # Get all current members
        all_members = db.query(GroupMember).filter(
            GroupMember.group_id == group_id
        ).all()
        
        # Delete old keys
        db.query(GroupKey).filter(GroupKey.group_id == group_id).delete()
        
        # Re-encrypt for all existing members
        for member in all_members:
            device = db.query(Device).filter(
                Device.user_id == member.user_id
            ).order_by(Device.created_at.desc()).first()
            
            if device:
                encrypted_key_data = encrypt_group_key_for_user(
                    group_aes_key,
                    device.pubkey_b64
                )
                
                new_key = GroupKey(
                    group_id=group_id,
                    user_id=member.user_id,
                    encrypted_group_key=json.dumps(encrypted_key_data),
                    algorithm="Kyber512+AES256"
                )
                db.add(new_key)
        
        # Add new member
        group_member = GroupMember(
            group_id=group_id,
            user_id=new_member_user.id
        )
        db.add(group_member)
        
        # Encrypt group key for new member
        encrypted_key_data = encrypt_group_key_for_user(
            group_aes_key,
            member_device.pubkey_b64
        )
        
        group_key = GroupKey(
            group_id=group_id,
            user_id=new_member_user.id,
            encrypted_group_key=json.dumps(encrypted_key_data),
            algorithm="Kyber512+AES256"
        )
        db.add(group_key)
        
        db.commit()
        
        return {
            "success": True,
            "message": f"Added {member_data.email} to group",
            "user_id": new_member_user.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error adding member: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to add member: {str(e)}")


@router.delete("/{group_id}/leave")
async def leave_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Leave a group (removes self from group)"""
    try:
        # Check if user is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == current_user.id
        ).first()
        
        if not membership:
            raise HTTPException(status_code=404, detail="You are not a member of this group")
        
        # Get group
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Check if user is the creator
        if group.created_by == current_user.id:
            # If creator leaves, check if there are other members
            member_count = db.query(GroupMember).filter(
                GroupMember.group_id == group_id
            ).count()
            
            if member_count > 1:
                raise HTTPException(
                    status_code=400,
                    detail="Group creator cannot leave while other members exist. Delete the group instead."
                )
        
        # Remove membership
        db.delete(membership)
        
        # Remove group key for this user
        group_key = db.query(GroupKey).filter(
            GroupKey.group_id == group_id,
            GroupKey.user_id == current_user.id
        ).first()
        if group_key:
            db.delete(group_key)
        
        # KEY ROTATION: Regenerate group key for remaining members
        remaining_members = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id != current_user.id
        ).all()
        
        if remaining_members:
            # Generate new group key
            new_group_aes_key = generate_group_aes_key()
            
            # Delete old keys for remaining members
            db.query(GroupKey).filter(
                GroupKey.group_id == group_id
            ).delete()
            
            # Re-encrypt for remaining members
            for member in remaining_members:
                device = db.query(Device).filter(
                    Device.user_id == member.user_id
                ).order_by(Device.created_at.desc()).first()
                
                if device:
                    encrypted_key_data = encrypt_group_key_for_user(
                        new_group_aes_key,
                        device.pubkey_b64
                    )
                    
                    new_key = GroupKey(
                        group_id=group_id,
                        user_id=member.user_id,
                        encrypted_group_key=json.dumps(encrypted_key_data),
                        algorithm="Kyber512+AES256"
                    )
                    db.add(new_key)
        
        db.commit()
        
        return {
            "success": True,
            "message": "Left group successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error leaving group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{group_id}")
async def delete_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a group (creator only)"""
    try:
        # Get group
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Check if user is the creator
        if group.created_by != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="Only the group creator can delete the group"
            )
        
        # Delete group (cascade will handle members and keys)
        db.delete(group)
        db.commit()
        
        return {
            "success": True,
            "message": "Group deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error deleting group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{group_id}/key")
async def get_group_key(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get encrypted group key for current user"""
    try:
        # Check if user is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == current_user.id
        ).first()
        
        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
        
        # Get encrypted group key
        group_key = db.query(GroupKey).filter(
            GroupKey.group_id == group_id,
            GroupKey.user_id == current_user.id
        ).first()
        
        if not group_key:
            raise HTTPException(status_code=404, detail="Group key not found")
        
        return {
            "group_id": group_id,
            "encrypted_group_key": group_key.encrypted_group_key,
            "algorithm": group_key.algorithm
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting group key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{group_id}/send")
async def send_group_message(
    group_id: int,
    message_data: SendGroupMessageRequest,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token),
    db: Session = Depends(get_db)
):
    """Send encrypted message to all group members"""
    try:
        # Check if user is a member
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id == current_user.id
        ).first()
        
        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this group")
        
        # Get group details
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Get sender's encrypted group key
        sender_group_key = db.query(GroupKey).filter(
            GroupKey.group_id == group_id,
            GroupKey.user_id == current_user.id
        ).first()
        
        if not sender_group_key:
            raise HTTPException(status_code=404, detail="Group key not found for sender")
        
        # For encryption, we need the actual AES key
        # The sender needs to decrypt it client-side first, but for this MVP
        # we'll generate a temporary key that matches what the frontend will use
        
        # NOTE: In the actual flow, the frontend will:
        # 1. Fetch encrypted group key
        # 2. Decrypt it using their Kyber private key (in IndexedDB)
        # 3. Use the decrypted AES key to encrypt the message
        # 4. Send the encrypted message here
        
        # For now, we'll assume the message is already encrypted by the frontend
        # and we just need to send it to all members
        
        # Get all group members
        members = db.query(GroupMember).filter(
            GroupMember.group_id == group_id
        ).all()
        
        # Get member emails
        recipient_emails = []
        for member in members:
            user = db.query(User).filter(User.id == member.user_id).first()
            if user:
                recipient_emails.append(user.email)
        
        if not recipient_emails:
            raise HTTPException(status_code=400, detail="No members found in group")
        
        # Initialize Gmail service
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        # The message comes pre-encrypted from frontend
        # Frontend will send the encrypted data in the message field
        
        # Format: subject will be [Group: TeamName] Original Subject
        formatted_subject = f"[Group: {group.name}] {message_data.subject}"
        
        # Create email body with encryption markers
        email_body = f"""╔═══════════════════════════════════════╗
🔐 ENCRYPTED GROUP MESSAGE - QMAIL
This message can only be read in QMail.
Sign in at: https://qmail-frontend.onrender.com
╚═══════════════════════════════════════╝

Group: {group.name}
Group ID: {group_id}

{message_data.message}

Encryption: Kyber512 + AES-256-GCM (Group Level 2)

---
Sent from QMail - Quantum-Secure Email
"""
        
        # Send to all recipients as a single email
        result = gmail.send_message(
            to=", ".join(recipient_emails),  # All recipients in TO field
            subject=formatted_subject,
            body=email_body
        )
        
        return {
            "success": True,
            "message_id": result['id'],
            "group_id": group_id,
            "group_name": group.name,
            "recipient_count": len(recipient_emails),
            "message": f"Group message sent to {len(recipient_emails)} members"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sending group message: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to send group message: {str(e)}")
