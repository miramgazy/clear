
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import secrets
import hashlib
from dependencies import increment_admin_revision
from ws_router import manager
from fastapi import APIRouter, Depends, Request
from cache import auth_cache, tokens_cache, settings_cache, accessible_ids_cache, rights_cache, users_cache
from database import get_db
from dependencies import require_manage_settings, require_read_log, require_superadmin
from utils import log_event
from models import LocalTokenReq, ServerSettingsReq

router = APIRouter(prefix="/admin", tags=["Admin System"])

@router.get("/tokens")
async def get_tokens(user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    cached_tokens = tokens_cache.get("all")
    if cached_tokens: return cached_tokens

    res = await db.execute(text("SELECT id, description, expires_at, created_at, is_active FROM localtokens"))
    rows = res.fetchall()
    
    result = [{
        "id": r[0], 
        "description": r[1], 
        "expires_at": r[2].strftime("%Y-%m-%d %H:%M:%S") if r[2] else None, 
        "created_at": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else None, 
        "is_active": r[4]
    } for r in rows]
    
    tokens_cache.set("all", result)
    return result

@router.post("/tokens")
async def create_token(req: LocalTokenReq, request: Request, user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    raw_token = "cl_" + secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_id = secrets.token_hex(8)
    
    if req.days_valid:
        await db.execute(text(f"INSERT INTO localtokens (id, token_hash, description, expires_at) VALUES (:id, :hash, :desc, now() + interval '{req.days_valid} days')"), 
                       {"id": token_id, "hash": token_hash, "desc": req.description})
    else:
        await db.execute(text("INSERT INTO localtokens (id, token_hash, description, expires_at) VALUES (:id, :hash, :desc, NULL)"), 
                       {"id": token_id, "hash": token_hash, "desc": req.description})
    
    token_user_id = f"local_token_{token_id}"
    await db.execute(text("INSERT INTO users (id, username, email, is_approved) VALUES (:id, :uname, '', True)"), 
                   {"id": token_user_id, "uname": f"Token: {req.description}"})
    
    res = await db.execute(text("SELECT value FROM serversettings WHERE key = 'DefaultGroupId'"))
    def_grp = res.fetchone()
    if def_grp and def_grp[0]:
        await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:uid, :gid)"), {"uid": token_user_id, "gid": def_grp[0]})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    tokens_cache.clear()
    users_cache.clear()
    await log_event(db, "Settings", user, request.client.host, f"Created new local token: {req.description}")
    return {"status": "ok", "token": raw_token}

@router.delete("/tokens/{token_id}")
async def revoke_token(request: Request, token_id: str, user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE localtokens SET is_active = False WHERE id = :id"), {"id": token_id})
    await db.execute(text("UPDATE users SET is_active = False WHERE id = :uid"), {"uid": f"local_token_{token_id}"})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    await log_event(db, "Settings", user, request.client.host, f"Disabled local token: {token_id}")
    
    auth_cache.clear()
    tokens_cache.clear()
    users_cache.clear()
    return {"status": "ok"}

@router.post("/tokens/{token_id}/restore")
async def restore_token(request: Request, token_id: str, user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE localtokens SET is_active = True WHERE id = :id"), {"id": token_id})
    await db.execute(text("UPDATE users SET is_active = True WHERE id = :uid"), {"uid": f"local_token_{token_id}"})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    auth_cache.clear()
    tokens_cache.clear()
    return {"status": "ok"}

@router.get("/settings")
async def get_settings(user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    cached_settings = settings_cache.get("all")
    if cached_settings: return cached_settings

    res = await db.execute(text("SELECT key, value FROM serversettings"))
    rows = res.fetchall()
    s = {r[0]: r[1] for r in rows}
    result = {"audit_retention_days": int(s.get("AuditRetentionDays", 90)), "deleted_retention_days": int(s.get("DeletedRetentionDays", 30)), "default_group_id": s.get("DefaultGroupId", "")}
    
    settings_cache.set("all", result)
    return result

@router.post("/settings")
async def save_settings(settings: ServerSettingsReq, request: Request, user = Depends(require_manage_settings), db: AsyncSession = Depends(get_db)):
    await db.execute(text("INSERT INTO serversettings (key, value) VALUES ('AuditRetentionDays', :val) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"), {"val": str(settings.audit_retention_days)})
    await db.execute(text("INSERT INTO serversettings (key, value) VALUES ('DeletedRetentionDays', :val) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"), {"val": str(settings.deleted_retention_days)})
    await db.execute(text("INSERT INTO serversettings (key, value) VALUES ('DefaultGroupId', :val) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"), {"val": settings.default_group_id})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Settings", user, request.client.host, "Changed system settings.")
    settings_cache.clear()
    return {"status": "ok"}

@router.delete("/wipe")
async def wipe_database(request: Request, user = Depends(require_superadmin), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
    await db.execute(text("UPDATE entities SET deleted = True, encrypted_data = '', revision = (SELECT revision FROM dbversion LIMIT 1)"))

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Deletion", user, request.client.host, "WARNING: COMPLETE SERVER DATA WIPE PERFORMED!")
    accessible_ids_cache.clear()
    rights_cache.clear()
    return {"status": "ok"}

@router.get("/auditlog")
async def get_audit_log(user = Depends(require_read_log), db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("SELECT timestamp, event_type, username, email, ip_address, details FROM auditlog ORDER BY id DESC LIMIT 3000"))
    rows = res.fetchall()
    return [{"timestamp": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else None, "event_type": r[1], "username": r[2], "email": r[3], "ip_address": r[4], "details": r[5]} for r in rows]