from fastapi import Depends, HTTPException, status, Cookie, Header
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
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from session cookie OR Authorization header
    
    This supports both:
    1. Cookie-based auth (same-origin requests)
    2. Bearer token in Authorization header (cross-origin requests)
    """
    
    # Try to get token from Authorization header first (for cross-origin)
    token = None
    
    if authorization and authorization.startswith('Bearer '):
        token = authorization.replace('Bearer ', '')
        print(f"✓ Token from Authorization header")
    elif session_token:
        token = session_token
        print(f"✓ Token from Cookie")
    
    if not token:
        print(f"✗ No token found in Cookie or Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify JWT token
    payload = verify_token(token)
    if not payload:
        print(f"✗ Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: int = payload.get("sub")
    if user_id is None:
        print(f"✗ No user_id in token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Convert to integer if it's a string (JWT spec requires sub to be string)
    if isinstance(user_id, str):
        try:
            user_id = int(user_id)
        except ValueError:
            print(f"✗ Invalid user_id format: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        print(f"✗ User {user_id} not found in database")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    print(f"✓ User authenticated: {user.email}")
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
