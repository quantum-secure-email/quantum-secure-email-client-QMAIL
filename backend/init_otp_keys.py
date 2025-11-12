from database import SessionLocal
from models import KMStore
import os
import base64
import uuid

def init_otp_keys(num_keys=100, key_size=1024):
    """Initialize OTP keys in database"""
    db = SessionLocal()
    try:
        # Check if keys already exist
        existing_count = db.query(KMStore).count()
        if existing_count > 0:
            print(f"OTP keys already initialized ({existing_count} keys found)")
            return
        
        # Generate keys
        print(f"Generating {num_keys} OTP keys...")
        for i in range(num_keys):
            key_id = str(uuid.uuid4())
            raw_key = os.urandom(key_size)
            key_b64 = base64.b64encode(raw_key).decode()
            
            otp_key = KMStore(
                key_id=key_id,
                key_b64=key_b64,
                used=False,
                origin="sim-qkd",
                meta={"size": key_size, "index": i}
            )
            db.add(otp_key)
            
            if (i + 1) % 10 == 0:
                print(f"Generated {i + 1}/{num_keys} keys...")
        
        db.commit()
        print(f"✓ Successfully initialized {num_keys} OTP keys")
        
    except Exception as e:
        print(f"Error initializing OTP keys: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_otp_keys()
