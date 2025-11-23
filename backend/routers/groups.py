"""
Groups Router - Manage encrypted group communications
Implements:
- Group creation with automatic AES key generation
- Member management (add/remove)
- Key rotation when members leave
- Group key retrieval for decryption
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import os
import base64

from database import get_db
from models import User, Group, GroupMember, GroupKey, Device
from dependencies import get_current_user

# PQC imports
try:
    import oqs
    kem = oqs.KeyEncapsulation("Kyber512")
except:
    kem = None
    print("WARNING: liboqs not available - PQC encryption disabled")

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

router = APIRouter(prefix="/groups", tags=["groups"])


# ==================== Request/Response Models ====================

class CreateGroupRequest(BaseModel):
    name: str
    member_emails: List[str] = []  # Optional initial members


class AddMemberRequest(BaseModel):
    email: str


class GroupResponse(BaseModel):
    id: int
    name: str
    created_by: int
    creator_email: str
    member_count: int
    created_at: datetime
    updated_at: datetime
    is_creator: bool


class GroupMemberResponse(BaseModel):
    user_id: int
    email: str
    name: Optional[str]
    joined_at: datetime


class GroupKeyResponse(BaseModel):
    encrypted_group_key: str  # Base64 encoded
    algorithm: str


# ==================== Helper Functions ====================

def generate_group_aes_key() -> str:
    """Generate a new 256-bit AES key for group encryption"""
    key_bytes = os.urandom(32)  # 256 bits
    return base64.b64encode(key_bytes).decode()


def encrypt_group_key_for_user(group_aes_key_b64: str, user_pubkey_b64: str) -> str:
    """
    Encrypt group AES key with user's Kyber512 public key
    Returns: encrypted_key_b64
    """
    if not kem:
        raise HTTPException(
            status_code=500,
            detail="PQC encryption not available"
        )
    
    # Decode group AES key
    group_aes_key = base64.b64decode(group_aes_key_b64)
    
    # Perform KEM encapsulation
    kem_ct_b64, shared_secret_b64 = kem.encapsulate(user_pubkey_b64)
    shared_secret = base64.b64decode(shared_secret_b64)
    
    # Derive AES key from shared secret (same as Level 2)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    aes_wrapper_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qmail-group-key-wrap"
    ).derive(shared_secret)
    
    # Encrypt group key with derived AES key
    aesgcm = AESGCM(aes_wrapper_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, group_aes_key, None)
    
    # Format: kem_ct||nonce||ciphertext (all base64)
    encrypted_package = {
        "kem_ct": kem_ct_b64,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    
    # Serialize to JSON-like string
    import json
    return base64.b64encode(json.dumps(encrypted_package).encode()).decode()


def rotate_group_keys(db: Session, group: Group, remaining_user_ids: List[int]):
    """
    Generate new group AES key and re-encrypt for all remaining members
    Called when a member leaves
    """
    # Generate new AES key
    new_aes_key_b64 = generate_group_aes_key()
    group.aes_key_b64 = new_aes_key_b64
    
    # Delete old keys
    db.query(GroupKey).filter(GroupKey.group_id == group.id).delete()
    
    # Encrypt new key for each remaining member
    for user_id in remaining_user_ids:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            continue
        
        # Get user's most recent device
        device = db.query(Device).filter(
            Device.user_id == user_id
        ).order_by(Device.created_at.desc()).first()
        
        if not device:
            print(f"WARNING: User {user.email} has no devices, skipping key rotation")
            continue
        
        # Encrypt group key with user's public key
        try:
            encrypted_key = encrypt_group_key_for_user(new_aes_key_b64, device.pubkey_b64)
            
            # Store encrypted key
            group_key = GroupKey(
                group_id=group.id,
                user_id=user_id,
                encrypted_group_key=encrypted_key,
                algorithm="Kyber512+AES256"
            )
            db.add(group_key)
        except Exception as e:
            print(f"ERROR encrypting key for {user.email}: {e}")
    
    db.commit()


# ==================== API Endpoints ====================

@router.post("", response_model=GroupResponse)
def create_group(
    request: CreateGroupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new group with encrypted messaging
    - Generates AES-256 group key
    - Adds creator as first member
    - Optionally adds initial members
    """
    
    # Generate group AES key
    group_aes_key_b64 = generate_group_aes_key()
    
    # Create group
    group = Group(
        name=request.name,
        created_by=current_user.id,
        aes_key_b64=group_aes_key_b64
    )
    db.add(group)
    db.flush()  # Get group.id
    
    # Add creator as first member
    creator_member = GroupMember(
        group_id=group.id,
        user_id=current_user.id
    )
    db.add(creator_member)
    
    # Get creator's most recent device
    creator_device = db.query(Device).filter(
        Device.user_id == current_user.id
    ).order_by(Device.created_at.desc()).first()
    
    if not creator_device:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="You must have a registered device to create groups"
        )
    
    # Encrypt group key for creator
    encrypted_key = encrypt_group_key_for_user(group_aes_key_b64, creator_device.pubkey_b64)
    creator_key = GroupKey(
        group_id=group.id,
        user_id=current_user.id,
        encrypted_group_key=encrypted_key,
        algorithm="Kyber512+AES256"
    )
    db.add(creator_key)
    
    # Add initial members if provided
    for email in request.member_emails:
        if email == current_user.email:
            continue  # Skip creator
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"WARNING: User {email} not found, skipping")
            continue
        
        # Check if already member
        existing = db.query(GroupMember).filter(
            GroupMember.group_id == group.id,
            GroupMember.user_id == user.id
        ).first()
        if existing:
            continue
        
        # Get user's most recent device
        device = db.query(Device).filter(
            Device.user_id == user.id
        ).order_by(Device.created_at.desc()).first()
        
        if not device:
            print(f"WARNING: User {email} has no devices, skipping")
            continue
        
        # Add as member
        member = GroupMember(
            group_id=group.id,
            user_id=user.id
        )
        db.add(member)
        
        # Encrypt group key for member
        try:
            encrypted_key = encrypt_group_key_for_user(group_aes_key_b64, device.pubkey_b64)
            member_key = GroupKey(
                group_id=group.id,
                user_id=user.id,
                encrypted_group_key=encrypted_key,
                algorithm="Kyber512+AES256"
            )
            db.add(member_key)
        except Exception as e:
            print(f"ERROR encrypting key for {email}: {e}")
    
    db.commit()
    db.refresh(group)
    
    # Count members
    member_count = db.query(GroupMember).filter(GroupMember.group_id == group.id).count()
    
    return GroupResponse(
        id=group.id,
        name=group.name,
        created_by=group.created_by,
        creator_email=current_user.email,
        member_count=member_count,
        created_at=group.created_at,
        updated_at=group.updated_at,
        is_creator=True
    )


@router.get("", response_model=List[GroupResponse])
def list_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all groups the current user is a member of
    """
    # Get all groups where user is a member
    memberships = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id
    ).all()
    
    groups_response = []
    for membership in memberships:
        group = db.query(Group).filter(Group.id == membership.group_id).first()
        if not group:
            continue
        
        creator = db.query(User).filter(User.id == group.created_by).first()
        member_count = db.query(GroupMember).filter(GroupMember.group_id == group.id).count()
        
        groups_response.append(GroupResponse(
            id=group.id,
            name=group.name,
            created_by=group.created_by,
            creator_email=creator.email if creator else "Unknown",
            member_count=member_count,
            created_at=group.created_at,
            updated_at=group.updated_at,
            is_creator=(group.created_by == current_user.id)
        ))
    
    return groups_response


@router.get("/{group_id}", response_model=GroupResponse)
def get_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get group details"""
    
    # Check membership
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
    
    creator = db.query(User).filter(User.id == group.created_by).first()
    member_count = db.query(GroupMember).filter(GroupMember.group_id == group_id).count()
    
    return GroupResponse(
        id=group.id,
        name=group.name,
        created_by=group.created_by,
        creator_email=creator.email if creator else "Unknown",
        member_count=member_count,
        created_at=group.created_at,
        updated_at=group.updated_at,
        is_creator=(group.created_by == current_user.id)
    )


@router.get("/{group_id}/members", response_model=List[GroupMemberResponse])
def get_group_members(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all members of a group"""
    
    # Check membership
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You are not a member of this group"
        )
    
    members = db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
    
    members_response = []
    for member in members:
        user = db.query(User).filter(User.id == member.user_id).first()
        if user:
            members_response.append(GroupMemberResponse(
                user_id=user.id,
                email=user.email,
                name=user.name,
                joined_at=member.joined_at
            ))
    
    return members_response


@router.post("/{group_id}/members")
def add_member(
    group_id: int,
    request: AddMemberRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Add a member to the group (only group creator can do this)
    """
    
    # Check if current user is creator
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.created_by != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the group creator can add members"
        )
    
    # Find user to add
    user_to_add = db.query(User).filter(User.email == request.email).first()
    if not user_to_add:
        raise HTTPException(
            status_code=404,
            detail=f"User {request.email} not found. They must sign in to QMail first."
        )
    
    # Check if already a member
    existing = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == user_to_add.id
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"{request.email} is already a member"
        )
    
    # Get user's most recent device
    device = db.query(Device).filter(
        Device.user_id == user_to_add.id
    ).order_by(Device.created_at.desc()).first()
    
    if not device:
        raise HTTPException(
            status_code=400,
            detail=f"{request.email} has no registered devices"
        )
    
    # Add as member
    new_member = GroupMember(
        group_id=group_id,
        user_id=user_to_add.id
    )
    db.add(new_member)
    
    # Encrypt group key for new member
    try:
        encrypted_key = encrypt_group_key_for_user(group.aes_key_b64, device.pubkey_b64)
        member_key = GroupKey(
            group_id=group_id,
            user_id=user_to_add.id,
            encrypted_group_key=encrypted_key,
            algorithm="Kyber512+AES256"
        )
        db.add(member_key)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to encrypt group key: {str(e)}"
        )
    
    db.commit()
    
    return {
        "success": True,
        "message": f"{request.email} added to group",
        "user_id": user_to_add.id
    }


@router.delete("/{group_id}/members/{user_id}")
def remove_member(
    group_id: int,
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Remove a member from the group
    - Member can only remove themselves
    - Triggers key rotation for security
    """
    
    # Check if user is trying to remove themselves
    if user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You can only remove yourself from a group"
        )
    
    # Check membership
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == user_id
    ).first()
    
    if not membership:
        raise HTTPException(
            status_code=404,
            detail="Member not found in group"
        )
    
    # Get group
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Prevent creator from leaving if there are other members
    if group.created_by == user_id:
        member_count = db.query(GroupMember).filter(GroupMember.group_id == group_id).count()
        if member_count > 1:
            raise HTTPException(
                status_code=400,
                detail="Group creator cannot leave while others are members. Delete the group instead."
            )
    
    # Remove member
    db.delete(membership)
    
    # Remove their group key
    db.query(GroupKey).filter(
        GroupKey.group_id == group_id,
        GroupKey.user_id == user_id
    ).delete()
    
    # Get remaining members
    remaining_members = db.query(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    if len(remaining_members) == 0:
        # If no members left, delete group
        db.delete(group)
    else:
        # Rotate keys for security
        remaining_user_ids = [m.user_id for m in remaining_members]
        rotate_group_keys(db, group, remaining_user_ids)
    
    db.commit()
    
    return {
        "success": True,
        "message": "Successfully left group",
        "key_rotated": len(remaining_members) > 0
    }


@router.get("/{group_id}/key", response_model=GroupKeyResponse)
def get_group_key(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the encrypted group key for the current user
    Used for client-side decryption
    """
    
    # Check membership
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You are not a member of this group"
        )
    
    # Get encrypted group key
    group_key = db.query(GroupKey).filter(
        GroupKey.group_id == group_id,
        GroupKey.user_id == current_user.id
    ).first()
    
    if not group_key:
        raise HTTPException(
            status_code=404,
            detail="Group key not found for your account"
        )
    
    return GroupKeyResponse(
        encrypted_group_key=group_key.encrypted_group_key,
        algorithm=group_key.algorithm
    )


@router.delete("/{group_id}")
def delete_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a group (only creator can do this)
    """
    
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.created_by != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the group creator can delete the group"
        )
    
    # Delete group (cascade will delete members and keys)
    db.delete(group)
    db.commit()
    
    return {
        "success": True,
        "message": "Group deleted successfully"
    }
