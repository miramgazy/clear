from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import httpx
import hashlib
from datetime import datetime
from fastapi import Header, HTTPException, Depends
from config import CENTRAL_AUTH_URL
from database import get_db
from utils import get_user_id
from cache import auth_cache

async def verify_user(authorization: str = Header(...), db: AsyncSession = Depends(get_db)):
    if not authorization.startswith("Bearer "): 
        raise HTTPException(401, "Invalid token format")
    
    token = authorization.replace("Bearer ", "").strip()

    cached_user = auth_cache.get(token)
    if cached_user:
        return cached_user

    if token.startswith("cl_"):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        res = await db.execute(text("SELECT description, expires_at, id, is_active FROM localtokens WHERE token_hash = :hash"), {"hash": token_hash})
        row = res.fetchone()
        if not row: raise HTTPException(401, "Invalid or deleted local token")
        
        if row[3] is not None and not bool(row[3]):
            raise HTTPException(403, "Token is disabled")
            
        if row[1] and row[1] < datetime.now():
            raise HTTPException(401, "Local token has expired")
            
        result = {"email": f"local_token_{row[2]}", "username": f"Token: {row[0]}", "is_local_token": True}
        auth_cache.set(token, result)
        return result
    else:
        try:
            custom_headers = {
                "Authorization": authorization,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json"
            }
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{CENTRAL_AUTH_URL}/auth/verify", 
                    headers=custom_headers, 
                    follow_redirects=True, 
                    timeout=5.0
                )
                
                if resp.status_code != 200: 
                    print(f"\n[AUTH ERROR] Central server returned {resp.status_code}: {resp.text}\n")
                    raise HTTPException(401, "Invalid token from central auth")
                    
                user_data = resp.json()
                user_data["is_local_token"] = False 
                
        except httpx.RequestError as e:
            print(f"\n[NETWORK ERROR] Failed to connect to central auth server: {e}\n")
            raise HTTPException(401, "Central auth server unavailable")
            
        res = await db.execute(text("SELECT is_active FROM users WHERE id = :uid"), {"uid": get_user_id(user_data)})
        act_row = res.fetchone()
        if act_row and act_row[0] is not None and not bool(act_row[0]):
            raise HTTPException(403, "User account is disabled")

        auth_cache.set(token, user_data)
        return user_data

async def require_manage_roles(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    if user.get("is_local_token"): raise HTTPException(403, "Access denied for local tokens")
    user_id = get_user_id(user)
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND (g.is_superadmin = True OR g.can_manage_roles = True)"""), {"uid": user_id})
    if not res.fetchone(): raise HTTPException(403, "Insufficient permissions to manage roles and access")
    return user

async def require_manage_users(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    if user.get("is_local_token"): raise HTTPException(403, "Access denied for local tokens")
    user_id = get_user_id(user)
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND (g.is_superadmin = True OR g.can_manage_users = True)"""), {"uid": user_id})
    if not res.fetchone(): raise HTTPException(403, "Insufficient permissions to manage roles and access")
    return user

async def require_manage_settings(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    if user.get("is_local_token"): raise HTTPException(403, "Access denied for local tokens")
    user_id = get_user_id(user)
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND (g.is_superadmin = True OR g.can_manage_settings = True)"""), {"uid": user_id})
    if not res.fetchone(): raise HTTPException(403, "Insufficient permissions to manage settings")
    return user

async def require_read_log(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    if user.get("is_local_token"): raise HTTPException(403, "Access denied for local tokens")
    user_id = get_user_id(user)
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND (g.is_superadmin = True OR g.can_read_log = True)"""), {"uid": user_id})
    if not res.fetchone(): raise HTTPException(403, "Insufficient permissions to read event logs")
    return user

async def require_superadmin(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    if user.get("is_local_token"): raise HTTPException(403, "Access denied for local tokens")
    user_id = get_user_id(user)
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND g.is_superadmin = True"""), {"uid": user_id})
    if not res.fetchone(): raise HTTPException(403, "Super-Admin privileges required")
    return user

async def increment_admin_revision(db: AsyncSession) -> int:
    await db.execute(text("UPDATE dbversion SET admin_revision = admin_revision + 1"))
    res = await db.execute(text("SELECT admin_revision FROM dbversion LIMIT 1"))
    row = res.fetchone()
    return row[0] if row else 1