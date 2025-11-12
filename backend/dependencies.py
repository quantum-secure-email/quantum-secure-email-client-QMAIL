from fastapi import Depends, HTTPException, status, Cookie
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from models import User, OAuthToken
from auth_utils import verify_token
from datetime import datetime

security = HTTPBearer(auto_error=False)

async def get_current_user(
    session_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from session cookie
    """
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify JWT token
    payload = verify_token(session_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: int = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

async def get_valid_oauth_token(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> OAuthToken:
    """
    Get valid OAuth token for current user, refresh if needed
    """
    oauth_token = db.query(OAuthToken).filter(
        OAuthToken.user_id == current_user.id
    ).first()
    
    if not oauth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth token not found. Please re-authenticate."
        )
    
    # Check if token is expired
    if datetime.utcnow() >= oauth_token.expires_at:
        # TODO: Implement token refresh
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth token expired. Please re-authenticate."
        )
    
    return oauth_token
