"""
Device Management Routes - PostgreSQL Based
Handles device registration, lookup, and recipient checking
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional
import uuid

from database import get_db
from models import User, Device
from dependencies import get_current_user

router = APIRouter(prefix="/device", tags=["devices"])


# === Pydantic Models ===

class DeviceRegisterRequest(BaseModel):
    pubkey_b64: str
    device_name: Optional[str] = "Browser"
    algo: Optional[str] = "Kyber512"


class RecipientCheckResponse(BaseModel):
    email: str
    has_device: bool
    user_id: Optional[int] = None
    device_id: Optional[str] = None
    device_count: int = 0


# === Routes ===

@router.post("/register")
async def register_device(
    device_data: DeviceRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Register a new device for the current user
    - Generates unique device_id
    - Stores public key in PostgreSQL
    - Enforces no duplicate public keys per user
    """
    
    # Check if this public key already exists for this user
    existing_device = db.query(Device).filter(
        Device.user_id == current_user.id,
        Device.pubkey_b64 == device_data.pubkey_b64
    ).first()
    
    if existing_device:
        return {
            "device_id": existing_device.device_id,
            "status": "already_registered",
            "message": "This device is already registered"
        }
    
    # Create new device
    device_id = str(uuid.uuid4())
    new_device = Device(
        user_id=current_user.id,
        device_id=device_id,
        pubkey_b64=device_data.pubkey_b64,
        algo=device_data.algo,
        meta={"name": device_data.device_name}
    )
    
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    
    return {
        "device_id": device_id,
        "status": "registered",
        "message": "Device registered successfully"
    }


@router.get("/user/{user_id}")
async def get_user_devices(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all devices for a specific user (returns most recent first)"""
    
    devices = db.query(Device).filter(
        Device.user_id == user_id
    ).order_by(desc(Device.created_at)).all()
    
    return {
        "user_id": user_id,
        "device_count": len(devices),
        "devices": [
            {
                "device_id": d.device_id,
                "algo": d.algo,
                "meta": d.meta,
                "created_at": d.created_at.isoformat()
            }
            for d in devices
        ]
    }


@router.get("/pubkey/{device_id}")
async def get_device_pubkey(
    device_id: str,
    db: Session = Depends(get_db)
):
    """Get public key for a specific device (used during encryption)"""
    
    device = db.query(Device).filter(
        Device.device_id == device_id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )
    
    return {
        "device_id": device_id,
        "pubkey_b64": device.pubkey_b64,
        "algo": device.algo
    }


@router.get("/check-recipient/{email}")
async def check_recipient(
    email: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> RecipientCheckResponse:
    """
    Check if a recipient has a registered device (required for Level 2/3 encryption)
    
    This endpoint is called by the frontend during compose to:
    1. Check if recipient email exists in QMail
    2. Check if they have at least one registered device
    3. Return their most recent device_id for encryption
    """
    
    # Look up user by email
    recipient_user = db.query(User).filter(
        User.email == email.lower().strip()
    ).first()
    
    if not recipient_user:
        return RecipientCheckResponse(
            email=email,
            has_device=False,
            device_count=0
        )
    
    # Get most recent device for this user
    device = db.query(Device).filter(
        Device.user_id == recipient_user.id
    ).order_by(desc(Device.created_at)).first()
    
    # Count total devices
    device_count = db.query(Device).filter(
        Device.user_id == recipient_user.id
    ).count()
    
    if device:
        return RecipientCheckResponse(
            email=email,
            has_device=True,
            user_id=recipient_user.id,
            device_id=device.device_id,
            device_count=device_count
        )
    else:
        return RecipientCheckResponse(
            email=email,
            has_device=False,
            user_id=recipient_user.id,
            device_count=0
        )


@router.get("/my-devices")
async def get_my_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all devices for the current logged-in user"""
    
    devices = db.query(Device).filter(
        Device.user_id == current_user.id
    ).order_by(desc(Device.created_at)).all()
    
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "device_count": len(devices),
        "devices": [
            {
                "device_id": d.device_id,
                "algo": d.algo,
                "meta": d.meta,
                "created_at": d.created_at.isoformat()
            }
            for d in devices
        ]
    }
