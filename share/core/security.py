import bcrypt
import hashlib

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Try bcrypt first
    try:
        if bcrypt.checkpw(plain_password.encode(), hashed_password.encode()):
            return True
    except:
        pass
    
    # Legacy SHA256 fallback
    if len(hashed_password) == 64:
        sha256_hash = hashlib.sha256(plain_password.encode()).hexdigest()
        if sha256_hash == hashed_password:
            return True
            
    return False
