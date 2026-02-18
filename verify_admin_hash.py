import bcrypt

# Current hash from network_security.users
h = "$2b$12$o2aVvRC90Vo4ksLNoBwSheoWx/VQmF9Gx7j9EoIAC8vyYcLiT8eQ."
p = "pppp"

print(f"Bcrypt Match: {bcrypt.checkpw(p.encode(), h.encode())}")
