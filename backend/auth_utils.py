from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    
    # JWT spec requires 'sub' to be a string
    if 'sub' in to_encode and not isinstance(to_encode['sub'], str):
        to_encode['sub'] = str(to_encode['sub'])
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        print(f"✓ Token created with SECRET_KEY length: {len(SECRET_KEY)}")
        return encoded_jwt
    except Exception as e:
        print(f"✗ Error creating token: {e}")
        raise

def verify_token(token: str):
    """Verify and decode JWT token"""
    try:
        print(f"🔍 Verifying token (length: {len(token)})")
        print(f"🔍 Using SECRET_KEY length: {len(SECRET_KEY)}")
        print(f"🔍 Algorithm: {ALGORITHM}")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        print(f"✓ Token decoded successfully")
        print(f"✓ Payload: {payload}")
        
        # Check if token is expired
        exp = payload.get("exp")
        if exp:
            exp_datetime = datetime.fromtimestamp(exp)
            now = datetime.utcnow()
            if now > exp_datetime:
                print(f"✗ Token expired: {exp_datetime} < {now}")
                return None
            else:
                print(f"✓ Token valid until: {exp_datetime}")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        print(f"✗ Token verification failed: Token expired")
        return None
    except jwt.JWTClaimsError as e:
        print(f"✗ Token verification failed: Invalid claims - {e}")
        return None
    except JWTError as e:
        print(f"✗ Token verification failed: JWT Error - {e}")
        return None
    except Exception as e:
        print(f"✗ Token verification failed: Unexpected error - {e}")
        import traceback
        traceback.print_exc()
        return None

def hash_token(token: str) -> str:
    """Hash sensitive tokens for storage"""
    return pwd_context.hash(token)

def verify_hashed_token(plain_token: str, hashed_token: str) -> bool:
    """Verify a token against its hash"""
    return pwd_context.verify(plain_token, hashed_token)
