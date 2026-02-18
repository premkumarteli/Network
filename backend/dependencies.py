from fastapi import Request, HTTPException

def login_required(request: Request):
    if "user_id" not in request.session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return request.session.get("username")
