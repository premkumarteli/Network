import bcrypt
import hashlib

def verify_password(plain_password, hashed_password):
    # Try bcrypt
    try:
        if bcrypt.checkpw(plain_password.encode(), hashed_password.encode()):
            return True
    except Exception as e:
        print(f"Bcrypt fail: {e}")
        pass
    
    # Try SHA256 fallback (if 64 chars)
    if len(hashed_password) == 64:
        sha256_hash = hashlib.sha256(plain_password.encode()).hexdigest()
        if sha256_hash == hashed_password:
            return True
            
    return False

# Data from diag_users.py
admin_hash = "$2b$12$o2aVvRC90Vo4ksLNoBwSheoWx/VQmF9Gx7j9EoIAC8vyYcLiT8eQ."
user_pppp_hash = "07945ffdf58204ea9cfbaa5e2d56a521d824f5c40e84609ac9624ef896c2f521"

print(f"Testing admin with 'pppp': {verify_password('pppp', admin_hash)}")
print(f"Testing pppp with 'pppp': {verify_password('pppp', user_pppp_hash)}")
print(f"Testing random fail: {verify_password('wrong', admin_hash)}")
