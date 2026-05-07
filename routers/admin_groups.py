
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from dependencies import increment_admin_revision
from ws_router import manager
from fastapi import APIRouter, Depends, Request, HTTPException
from cache import groups_cache, rights_cache, accessible_ids_cache
from database import get_db
from dependencies import require_manage_roles
from utils import log_event, get_user_id
from models import GroupCreate, PermissionSetReq, InviteReq, GroupUsersReq

router = APIRouter(prefix="/admin", tags=["Admin Groups"])

@router.get("/groups")
async def get_groups(user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    cached_groups = groups_cache.get("all")
    if cached_groups: return cached_groups

    res = await db.execute(text("SELECT id, name, is_superadmin, can_manage_users, can_save_local, can_add, can_edit, can_delete, is_hidden, is_deleted, can_read_log, can_manage_roles, can_manage_settings FROM groups"))
    rows = res.fetchall()
    result = [{"id": r[0], "name": r[1], "is_superadmin": r[2], "can_manage_users": r[3], "can_save_local": r[4],
             "can_add": r[5], "can_edit": r[6], "can_delete": r[7], "is_hidden": r[8], "is_deleted": r[9],
             "can_read_log": r[10], "can_manage_roles": r[11], "can_manage_settings": r[12]} for r in rows]
    
    groups_cache.set("all", result)
    return result

@router.post("/groups")
async def create_group(g: GroupCreate, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("""SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :uid AND g.is_deleted = False AND g.is_superadmin = True"""), {"uid": get_user_id(user)})
    caller_is_super = res.fetchone() is not None

    if g.is_superadmin and not caller_is_super:
        raise HTTPException(403, "Only Super-Admin can create such groups.")
        
    res = await db.execute(text("SELECT is_superadmin FROM groups WHERE id = :id"), {"id": g.id})
    existing = res.fetchone()
    if existing and existing[0] is True and not caller_is_super:
        raise HTTPException(403, "You cannot modify the Super-Admin group.")

    await db.execute(text("""
        INSERT INTO groups (id, name, is_superadmin, can_manage_users, can_save_local, can_add, can_edit, can_delete, is_hidden, is_deleted, can_read_log, can_manage_roles, can_manage_settings) 
        VALUES (:id, :name, :is_sa, :cmu, :csl, :ca, :ce, :cd, :ih, :id_del, :crl, :cmr, :cms)
        ON CONFLICT (id) DO UPDATE SET 
            name = EXCLUDED.name,
            is_superadmin = EXCLUDED.is_superadmin,
            can_manage_users = EXCLUDED.can_manage_users,
            can_save_local = EXCLUDED.can_save_local,
            can_add = EXCLUDED.can_add,
            can_edit = EXCLUDED.can_edit,
            can_delete = EXCLUDED.can_delete,
            is_hidden = EXCLUDED.is_hidden,
            is_deleted = EXCLUDED.is_deleted,
            can_read_log = EXCLUDED.can_read_log,
            can_manage_roles = EXCLUDED.can_manage_roles,
            can_manage_settings = EXCLUDED.can_manage_settings
    """), {
        "id": g.id, "name": g.name, "is_sa": g.is_superadmin, "cmu": g.can_manage_users, "csl": g.can_save_local,
        "ca": g.can_add, "ce": g.can_edit, "cd": g.can_delete, "ih": g.is_hidden, "id_del": g.is_deleted,
        "crl": g.can_read_log, "cmr": g.can_manage_roles, "cms": g.can_manage_settings
    })

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    await log_event(db, "Rights change", user, request.client.host, f"Updated group: '{g.name}'")
    
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}

@router.delete("/groups/{group_id}")
async def delete_group(group_id: str, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("SELECT name FROM groups WHERE id = :id"), {"id": group_id})
    row = res.fetchone()
    g_name = row[0] if row else "Unknown"
    await db.execute(text("UPDATE groups SET is_deleted = True WHERE id = :id"), {"id": group_id})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    await log_event(db, "Deletion", user, request.client.host, f"Soft delete of group: '{g_name}'")
    
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}

@router.delete("/groups/{group_id}/permissions")
async def clear_group_permissions(group_id: str, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
    res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
    new_rev = res.scalar()
    
    await db.execute(text("""
        UPDATE entities SET revision = :rev WHERE id IN (
            WITH RECURSIVE children AS (
                SELECT entity_id AS id FROM entitypermissions WHERE group_id = :gid
                UNION ALL
                SELECT e.id FROM entities e JOIN children c ON e.folder_id = c.id
            )
            SELECT id FROM children
        )
    """), {"rev": new_rev, "gid": group_id})
    
    await db.execute(text("DELETE FROM entitypermissions WHERE group_id = :gid"), {"gid": group_id})
    
    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}

@router.get("/permissions")
async def get_permissions(user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("SELECT entity_id, group_id, access_level FROM entitypermissions"))
    rows = res.fetchall()
    return [{"entity_id": r[0], "group_id": r[1], "access_level": r[2]} for r in rows]

@router.post("/permissions")
async def set_permission(perm: PermissionSetReq, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    acc_level = normalize_access_level(perm.access_level)
    res = await db.execute(text("SELECT access_level FROM entitypermissions WHERE entity_id = :eid AND group_id = :gid"), {"eid": perm.entity_id, "gid": perm.group_id})
    current_perm = res.fetchone()
    if current_perm and current_perm[0] == acc_level:
        return {"status": "ok"}
        
    await db.execute(text("""
        INSERT INTO entitypermissions (entity_id, group_id, access_level) 
        VALUES (:eid, :gid, :al) 
        ON CONFLICT (entity_id, group_id) DO UPDATE SET access_level = EXCLUDED.access_level
    """), {"eid": perm.entity_id, "gid": perm.group_id, "al": acc_level})
    
    await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
    res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
    new_rev = res.scalar()
    
    await db.execute(text("""
        UPDATE entities SET revision = :rev WHERE id IN (
            WITH RECURSIVE children AS (
                SELECT id FROM entities WHERE id = :eid
                UNION ALL
                SELECT e.id FROM entities e JOIN children c ON e.folder_id = c.id
            )
            SELECT id FROM children
        )
    """), {"rev": new_rev, "eid": perm.entity_id})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}

@router.post("/groups/{group_id}/permissions/bulk")
async def save_group_permissions_bulk(
    group_id: str,
    permissions: list[PermissionSetReq],
    request: Request,
    user = Depends(require_manage_roles),
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(text("SELECT entity_id FROM entitypermissions WHERE group_id = :gid"), {"gid": group_id})
    old_ids = [r[0] for r in res.fetchall()]
    new_ids = [p.entity_id for p in permissions] if permissions else []
    affected_ids = list(set(old_ids + new_ids))

    await db.execute(text("DELETE FROM entitypermissions WHERE group_id = :gid"), {"gid": group_id})

    if permissions:
        for p in permissions:
            await db.execute(text("INSERT INTO entitypermissions (group_id, entity_id, access_level) VALUES (:gid, :eid, :al)"), 
                           {"gid": group_id, "eid": p.entity_id, "al": normalize_access_level(p.access_level)})

    await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
    res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
    new_rev = res.scalar()

    if affected_ids:
        # PostgreSQL handles array in IN clause with ANY or we can use SQLAlchemy expansion
        await db.execute(text("""
            UPDATE entities SET revision = :rev WHERE id IN (
                WITH RECURSIVE children AS (
                    SELECT id FROM entities WHERE id = ANY(:ids)
                    UNION ALL
                    SELECT e.id FROM entities e JOIN children c ON e.folder_id = c.id
                )
                SELECT id FROM children
            )
        """), {"rev": new_rev, "ids": affected_ids})
        
    await db.commit()
    
    await log_event(db, "Rights change", user, request.client.host, f"Bulk permission update for group {group_id}")

    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})

    await manager.broadcast({"event": "new_revision", "revision": new_rev})
    
    rights_cache.clear()
    accessible_ids_cache.clear()
    
    return {"status": "ok"}

@router.post("/invite")
async def invite_user(req: InviteReq, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:uid, :gid) ON CONFLICT DO NOTHING"), {"uid": req.user_id, "gid": req.group_id})

    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    res = await db.execute(text("SELECT name FROM groups WHERE id = :gid"), {"gid": req.group_id})
    row = res.fetchone()
    group_name = row[0] if row else "Unknown"
    await log_event(db, "Rights change", user, request.client.host, f"Invited user {req.user_id} (Group: {group_name})")
    
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}

@router.get("/groups/{group_id}/users")
async def get_group_users(group_id: str, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    res = await db.execute(text("SELECT user_id FROM usergroups WHERE group_id = :gid"), {"gid": group_id})
    rows = res.fetchall()
    return [r[0] for r in rows]

@router.post("/groups/{group_id}/users")
async def set_group_users(group_id: str, req: GroupUsersReq, request: Request, user = Depends(require_manage_roles), db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM usergroups WHERE group_id = :gid"), {"gid": group_id})
    for uid in req.user_ids: 
        await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:uid, :gid)"), {"uid": uid, "gid": group_id})
    await db.commit()
    new_admin_rev = await increment_admin_revision(db)
    await manager.broadcast({"event": "admin_revision", "revision": new_admin_rev})
    await log_event(db, "Rights change", user, request.client.host, f"Updated group users (Count: {len(req.user_ids)}) for group ID: {group_id}")
    
    groups_cache.clear()
    rights_cache.clear()
    accessible_ids_cache.clear()
    return {"status": "ok"}
    
def normalize_access_level(level: str) -> str:
    mapping = {
        'Нет доступа': 'none',
        'Чтение': 'read',
        'Чтение / Запись': 'write'
    }
    return mapping.get(level, level)