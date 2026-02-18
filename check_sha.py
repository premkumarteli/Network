import hashlib
p = "pppp"
h = hashlib.sha256(p.encode()).hexdigest()
print(f"SHA256 of '{p}': {h}")

db_h = "07945ffdf58204ea9cfbaa5e2d56a521d824f5c40e84609ac9624ef896c2f521"
print(f"Match: {h == db_h}")
