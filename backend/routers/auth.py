from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from datetime import datetime, timedelta
from typing import Optional
import os
from dotenv import load_dotenv

from database import get_db
from models import User, OAuthToken
from auth_utils import create_access_token, verify_token
from dependencies import get_current_user

load_dotenv()

router = APIRouter(prefix="/auth", tags=["authentication"])

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8080")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly"
]

@router.get("/login")
async def login():
    """Initiate OAuth flow"""
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    return RedirectResponse(url=authorization_url)


@router.get("/callback")
async def callback(code: str, state: str, db: Session = Depends(get_db)):
    """Handle OAuth callback"""
    try:
        # Exchange authorization code for tokens
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI,
            state=state
        )
        
        # Fetch token
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # Get user info from ID token
        idinfo = id_token.verify_oauth2_token(
            credentials.id_token,
            google_requests.Request()
        )
        
        # Manually verify this is our client's token
        aud = idinfo.get('aud', '')
        if GOOGLE_CLIENT_ID not in aud:
            raise ValueError(f"Token not for our application: {aud}")
        
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')
        picture = idinfo.get('picture', '')
        
        print(f"✓ OAuth successful for user: {email}")
        
        # Create or update user
        user = db.query(User).filter(User.google_id == google_id).first()
        
        if not user:
            user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"✓ Created new user: {email}")
        else:
            # Update user info
            user.email = email
            user.name = name
            user.picture = picture
            user.updated_at = datetime.utcnow()
            db.commit()
            print(f"✓ Updated existing user: {email}")
        
        # Store or update OAuth tokens
        oauth_token = db.query(OAuthToken).filter(
            OAuthToken.user_id == user.id
        ).first()
        
        # Calculate token expiry
        if credentials.expiry:
            expires_at = credentials.expiry
        else:
            expires_at = datetime.utcnow() + timedelta(hours=1)
        
        if oauth_token:
            oauth_token.access_token = credentials.token
            oauth_token.refresh_token = credentials.refresh_token or oauth_token.refresh_token
            oauth_token.expires_at = expires_at
            oauth_token.scope = ' '.join(SCOPES)
            oauth_token.updated_at = datetime.utcnow()
            print(f"✓ Updated OAuth token for user: {email}")
        else:
            oauth_token = OAuthToken(
                user_id=user.id,
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                expires_at=expires_at,
                scope=' '.join(SCOPES)
            )
            db.add(oauth_token)
            print(f"✓ Created new OAuth token for user: {email}")
        
        db.commit()
        
        # Create session token (JWT) with user info
        session_token = create_access_token(data={
            "sub": str(user.id),
            "email": email,
            "name": name,
            "picture": picture
        })
        print(f"✓ Created session token for user: {email}")
        
        # Redirect to frontend with session token
        redirect_url = f"{FRONTEND_URL}/auth/complete?token={session_token}"
        print(f"✓✓✓ Redirecting to: {redirect_url}")
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        print(f"✗ OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(url=f"{FRONTEND_URL}/?error=auth_failed")


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user"""
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="session_token")
    return response


# NEW: Updated /auth/me to support Authorization header
@router.get("/me")
async def get_current_user_info(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Get current user information from Authorization header"""
    # Extract token from Authorization header
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated - Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.replace('Bearer ', '')
    print(f"📍 Token received in /auth/me (length: {len(token)})")
    
    # Verify token
    payload = verify_token(token)
    if not payload:
        print(f"❌ Token verification failed in /auth/me")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    print(f"✓ Token verified in /auth/me, payload: {payload}")
    
    # Get user from database
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    print(f"✓ User found in /auth/me: {user.email}")
    
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture
    }