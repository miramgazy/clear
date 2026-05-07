from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from dependencies import increment_admin_revision, require_manage_users, require_manage_roles
from ws_router import manager
from fastapi import APIRouter, Depends, Request, HTTPException
from cache import auth_cache, rights_cache, accessible_ids_cache, users_cache, pending_cache, groups_cache
from database import get_db
from utils import log_event, get_user_id
from models import UserGroupUpdate
from datetime import datetime

router = APIRouter(prefix="/admin", tags=["Admin Users"])

@router.get("/users")
async def get_all_users(user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    cached_users = users_cache.get("all")
    
    if not cached_users:
        try:
            res = await db.execute(text("""
                SELECT u.id, u.username, u.email, u.last_connect, ug.group_id, u.is_active 
                FROM users u 
                LEFT JOIN usergroups ug ON u.id = ug.user_id 
                WHERE u.is_approved = True ORDER BY u.last_connect DESC
            """))
            rows = res.fetchall()
            
            cached_users = [{
                "id": r[0], 
                "username": r[1], 
                "email": r[2], 
                "last_connect": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else None, 
                "group_id": r[4] if r[4] else "", 
                "is_active": r[5] if r[5] is not None else True
            } for r in rows]
            
            users_cache.set("all", cached_users)
            
        except Exception as e:
            print(f"Database error while fetching users: {e}")
            return []

    result = []
    now = datetime.now()
    for u in cached_users:
        user_data = dict(u)
        is_online = False
        if user_data["last_connect"]:
            try:
                last_time = datetime.strptime(user_data["last_connect"], "%Y-%m-%d %H:%M:%S")
                if (now - last_time).total_seconds() < 15: 
                    is_online = True
            except:
                pass
        user_data["is_online"] = is_online
        result.append(user_data)

    return result

@router.get("/pending_users")
async def get_pending_users(user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    cached_pending = pending_cache.get("all")
    if cached_pending: return cached_pending

    res = await db.execute(text("SELECT id, username, email, first_connect FROM users WHERE is_approved = False ORDER BY first_connect DESC"))
    rows = res.fetchall()
    result = [{"id": r[0], "username": r[1], "email": r[2], "first_connect": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else None} for r in rows]
    
    pending_cache.set("all", result)
    return result

@router.post("/pending_users/{target_user_id}/approve")
async def approve_user(target_user_id: str, request: Request, user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE users SET is_approved = True, is_active = True WHERE id = :id"), {"id": target_user_id})
    
    res = await db.execute(text("SELECT value FROM serversettings WHERE key = 'DefaultGroupId'"))
    def_grp = res.fetchone()
    if def_grp and def_grp[0]:
        await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:uid, :gid) ON CONFLICT DO NOTHING"), {"uid": target_user_id, "gid": def_grp[0]})
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Rights change", user, request.client.host, f"Approved request for user {target_user_id}")
    
    auth_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    pending_cache.clear()
    users_cache.clear() 
    return {"status": "ok"}

@router.delete("/pending_users/{target_user_id}")
async def reject_user(target_user_id: str, request: Request, user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE users SET is_active = False WHERE id = :id"), {"id": target_user_id})
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    auth_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    pending_cache.clear()
    users_cache.clear() 
    return {"status": "ok"}

@router.post("/pending_users/{target_user_id}/restore")
async def restore_pending_user(target_user_id: str, request: Request, user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE users SET is_active = True WHERE id = :id"), {"id": target_user_id})
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    auth_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    pending_cache.clear()
    users_cache.clear() 
    return {"status": "ok"}

@router.put("/users/{target_user_id}/group")
async def set_user_group(target_user_id: str, req: UserGroupUpdate, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    if not req.group_id:
        await db.execute(text("DELETE FROM usergroups WHERE user_id = :uid"), {"uid": target_user_id})
    else:
        await db.execute(text("DELETE FROM usergroups WHERE user_id = :uid"), {"uid": target_user_id})
        await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:uid, :gid)"), {"uid": target_user_id, "gid": req.group_id})
        
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Rights change", user, request.client.host, f"Changed group for user {target_user_id}")
    
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    users_cache.clear()
    auth_cache.clear()
    return {"status": "ok"}

@router.delete("/users/{target_user_id}")
async def ban_user(target_user_id: str, request: Request, user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE users SET is_active = False WHERE id = :uid"), {"uid": target_user_id})
    
    if target_user_id.startswith("local_token_"):
        token_id = target_user_id.replace("local_token_", "")
        await db.execute(text("UPDATE localtokens SET is_active = False WHERE id = :tid"), {"tid": token_id})
        users_cache.clear() 
    
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Rights change", user, request.client.host, f"Account disabled: {target_user_id}")
    
    auth_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    users_cache.clear()
    
    return {"status": "ok"}

@router.post("/users/{target_user_id}/restore")
async def restore_user(target_user_id: str, request: Request, user = Depends(require_manage_users), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE users SET is_active = True WHERE id = :uid"), {"uid": target_user_id})
    await db.commit()
    
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await log_event(db, "Rights change", user, request.client.host, f"Account restored: {target_user_id}")
    
    auth_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    users_cache.clear()
    return {"status": "ok"}