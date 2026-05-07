from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import asyncio
from ws_router import manager
from cache import workspace_key_cache, rights_cache, accessible_ids_cache
from fastapi import APIRouter, Depends, HTTPException, Request
from database import get_db
from dependencies import verify_user
from utils import get_user_id, log_event
from models import SyncRequest
from datetime import datetime

router = APIRouter(prefix="/sync", tags=["Sync"])

db_write_lock = asyncio.Lock()

@router.get("/workspace_key")
async def get_workspace_key(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    
    cached_key = workspace_key_cache.get(user_id)
    if cached_key: return cached_key

    try:
        res = await db.execute(text("SELECT is_approved, is_active FROM users WHERE id = :user_id"), {"user_id": user_id})
        urow = res.fetchone()
    except Exception:
        res = await db.execute(text("SELECT is_approved, True FROM users WHERE id = :user_id"), {"user_id": user_id})
        urow = res.fetchone()
    
    if not urow or not urow[0]: 
        raise HTTPException(403, "No access to workspace key (not approved)")
    if urow[1] is not None and not bool(urow[1]): 
        raise HTTPException(403, "Account disabled")
        
    res = await db.execute(text("SELECT value FROM serversettings WHERE key = 'MasterKey'"))
    row = res.fetchone()
    
    result = {"key": row[0] if row else ""}
    workspace_key_cache.set(user_id, result)
    return result

@router.get("/my_rights")
async def get_my_rights(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    
    cached_rights = rights_cache.get(user_id)
    if cached_rights: return cached_rights

    username = user.get("username", "Unknown")
    email = user.get("email", "")

    res = await db.execute(text("SELECT is_approved FROM users WHERE id = :user_id"), {"user_id": user_id})
    user_row = res.fetchone()

    if not user_row:
        res = await db.execute(text("SELECT COUNT(*) FROM users"))
        total_users = res.scalar()
        
        res = await db.execute(text("SELECT COUNT(*) FROM usergroups WHERE user_id = :user_id"), {"user_id": user_id})
        is_invited = res.scalar() > 0

        if total_users == 0:
            await db.execute(text("INSERT INTO users (id, username, email, is_approved) VALUES (:id, :u, :e, True)"), {"id": user_id, "u": username, "e": email})
            await db.execute(text("INSERT INTO usergroups (user_id, group_id) VALUES (:id, 'admin_group')"), {"id": user_id})
            is_approved = True
        elif is_invited:
            await db.execute(text("INSERT INTO users (id, username, email, is_approved) VALUES (:id, :u, :e, True)"), {"id": user_id, "u": username, "e": email})
            is_approved = True
        else:
            await db.execute(text("INSERT INTO users (id, username, email, is_approved) VALUES (:id, :u, :e, False)"), {"id": user_id, "u": username, "e": email})
            is_approved = False
        await db.commit()
    else:
        is_approved = bool(user_row[0])
        try:
            res = await db.execute(text("SELECT is_active FROM users WHERE id = :user_id"), {"user_id": user_id})
            act_row = res.fetchone()
            if act_row and act_row[0] is not None and not bool(act_row[0]):
                raise HTTPException(403, "Account disabled by administrator")
        except HTTPException:
            raise
        except Exception:
            pass
        await db.execute(text("UPDATE users SET last_connect = now(), username = :u, email = :e WHERE id = :id"), {"u": username, "e": email, "id": user_id})
        await db.commit()

    r = { "is_superadmin": False, "can_add": False, "can_edit": False, "can_delete": False, "can_save_local": False, "can_manage_users": False, "can_read_log": False, "can_manage_roles": False, "can_manage_settings": False, "is_pending": not is_approved, "folders": {} }
    
    if not is_approved:
        rights_cache.set(user_id, r)
        return r

    res = await db.execute(text("""SELECT g.is_superadmin, g.can_add, g.can_edit, g.can_delete, g.can_save_local, g.can_manage_users, g.can_read_log, g.can_manage_roles, g.can_manage_settings 
                 FROM groups g JOIN usergroups ug ON g.id = ug.group_id WHERE ug.user_id = :user_id AND g.is_deleted = False"""), {"user_id": user_id})
    rows = res.fetchall()
    
    if rows:
        r["is_superadmin"] = any(x[0] for x in rows); r["can_add"] = any(x[1] for x in rows); r["can_edit"] = any(x[2] for x in rows)
        r["can_delete"] = any(x[3] for x in rows); r["can_save_local"] = any(x[4] for x in rows); r["can_manage_users"] = any(x[5] for x in rows)
        r["can_read_log"] = any(x[6] for x in rows); r["can_manage_roles"] = any(x[7] for x in rows); r["can_manage_settings"] = any(x[8] for x in rows)

    if r["is_superadmin"]:
        for k in r.keys(): 
            if k not in ["is_pending", "folders"]: r[k] = True

    if not r["is_superadmin"]:
        res = await db.execute(text("""
        WITH RECURSIVE
        EntityAccess AS (
            SELECT e.id, e.folder_id,
                CASE WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END AS HasRestrict,
                COALESCE((SELECT ep.access_level FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND g.is_deleted = False ORDER BY CASE ep.access_level WHEN 'none' THEN 1 WHEN 'write' THEN 2 WHEN 'read' THEN 3 END LIMIT 1), 'inherited') AS DirectAccess
            FROM entities e
            WHERE e.folder_id = '' OR e.folder_id IS NULL OR NOT EXISTS (SELECT 1 FROM entities p WHERE p.id = e.folder_id)

            UNION ALL

            SELECT e.id, e.folder_id,
                CASE WHEN ea.HasRestrict = True OR EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END,
                CASE
                    WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN
                        COALESCE((SELECT ep.access_level FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND g.is_deleted = False ORDER BY CASE ep.access_level WHEN 'none' THEN 1 WHEN 'write' THEN 2 WHEN 'read' THEN 3 END LIMIT 1), ea.DirectAccess)
                    ELSE ea.DirectAccess
                END
            FROM entities e
            JOIN EntityAccess ea ON e.folder_id = ea.id
        )
        SELECT id, DirectAccess FROM EntityAccess WHERE DirectAccess IN ('read', 'write')
        """), {"user_id": user_id})
        rows_folders = res.fetchall()
        r["folders"] = {row[0]: row[1] for row in rows_folders}

    rights_cache.set(user_id, r)
    return r

@router.get("/revision")
async def get_revision(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    try:
        await db.execute(text("UPDATE users SET last_connect = now() WHERE id = :user_id"), {"user_id": user_id})
        await db.commit()
    except Exception:
        pass
    res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
    rev_row = res.fetchone()
    return {"revision": rev_row[0] if rev_row else 0}

@router.get("/accessible_ids")
async def get_accessible_ids(user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    
    cached_ids = accessible_ids_cache.get(user_id)
    if cached_ids: return cached_ids

    res = await db.execute(text("SELECT is_approved FROM users WHERE id = :user_id"), {"user_id": user_id})
    row = res.fetchone()
    if not row or not row[0]: return []

    res = await db.execute(text("SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id WHERE ug.user_id = :user_id AND g.is_superadmin = True AND g.is_deleted = False"), {"user_id": user_id})
    is_super = res.fetchone() is not None

    if is_super:
        res = await db.execute(text("SELECT id FROM entities WHERE deleted = False"))
    else:
        query = """
        WITH RECURSIVE
        EntityAccess AS (
            SELECT e.id, e.folder_id,
                CASE WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END AS HasRestrict,
                CASE 
                    WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level = 'none' AND g.is_deleted = False) THEN False
                    WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level IN ('read', 'write') AND g.is_deleted = False) THEN True 
                    ELSE False 
                END AS HasAccess
            FROM entities e
            WHERE e.folder_id = '' OR e.folder_id IS NULL OR NOT EXISTS (SELECT 1 FROM entities p WHERE p.id = e.folder_id)

            UNION ALL

            SELECT e.id, e.folder_id,
                CASE WHEN ea.HasRestrict = True OR EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END,
                CASE
                    WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN
                        CASE 
                            WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level = 'none' AND g.is_deleted = 0) THEN 0
                            WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level IN ('read', 'write') AND g.is_deleted = 0) THEN 1 
                            ELSE ea.HasAccess 
                        END
                    ELSE ea.HasAccess
                END
            FROM entities e
            JOIN EntityAccess ea ON e.folder_id = ea.id
        )
        SELECT e.id
        FROM entities e
        JOIN EntityAccess ea ON e.id = ea.id
        WHERE e.deleted = False AND (ea.HasRestrict = False OR ea.HasAccess = True)
        """
        res = await db.execute(text(query), {"user_id": user_id})

    rows = res.fetchall()
    result = [r[0] for r in rows]
    accessible_ids_cache.set(user_id, result)
    return result

@router.get("/pull")
async def pull_data(since_revision: int = 0, request: Request = None, user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    
    res = await db.execute(text("SELECT is_approved FROM users WHERE id = :user_id"), {"user_id": user_id})
    row = res.fetchone()
    if not row or not row[0]: return []

    res = await db.execute(text("SELECT 1 FROM groups g JOIN usergroups ug ON g.id = ug.group_id WHERE ug.user_id = :user_id AND g.is_superadmin = True AND g.is_deleted = False"), {"user_id": user_id})
    is_super = res.fetchone() is not None

    if is_super:
        res = await db.execute(text("SELECT id, encrypted_data, deleted, revision FROM entities WHERE revision > :rev"), {"rev": since_revision})
    else:
        query = """
        WITH RECURSIVE
        EntityAccess AS (
            SELECT e.id, e.folder_id,
                CASE WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END AS HasRestrict,
                CASE 
                    WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level = 'none' AND g.is_deleted = False) THEN False
                    WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level IN ('read', 'write') AND g.is_deleted = False) THEN True 
                    ELSE False 
                END AS HasAccess
            FROM entities e
            WHERE e.folder_id = '' OR e.folder_id IS NULL OR NOT EXISTS (SELECT 1 FROM entities p WHERE p.id = e.folder_id)

            UNION ALL

            SELECT e.id, e.folder_id,
                CASE WHEN ea.HasRestrict = True OR EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN True ELSE False END,
                CASE
                    WHEN EXISTS (SELECT 1 FROM entitypermissions WHERE entity_id = e.id) THEN
                        CASE 
                            WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level = 'none' AND g.is_deleted = 0) THEN 0
                            WHEN EXISTS (SELECT 1 FROM entitypermissions ep JOIN usergroups ug ON ep.group_id = ug.group_id JOIN groups g ON g.id = ug.group_id WHERE ep.entity_id = e.id AND ug.user_id = :user_id AND ep.access_level IN ('read', 'write') AND g.is_deleted = 0) THEN 1 
                            ELSE ea.HasAccess 
                        END
                    ELSE ea.HasAccess
                END
            FROM entities e
            JOIN EntityAccess ea ON e.folder_id = ea.id
        )
        SELECT e.id, e.encrypted_data, e.deleted, e.revision
        FROM entities e
        JOIN EntityAccess ea ON e.id = ea.id
        WHERE e.revision > :rev AND (ea.HasRestrict = False OR ea.HasAccess = True)
        """
        res = await db.execute(text(query), {"user_id": user_id, "rev": since_revision})

    rows = res.fetchall()
    return [{"id": r[0], "encrypted_data": r[1], "deleted": bool(r[2]), "revision": r[3]} for r in rows]

@router.post("/push")
async def push_data(req: SyncRequest, request: Request, user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)

    res = await db.execute(text("SELECT is_approved FROM users WHERE id = :user_id"), {"user_id": user_id})
    row = res.fetchone()
    if not row or not row[0]: 
        raise HTTPException(403, "Access denied: user is in quarantine.")

    is_super = can_add = can_edit = can_delete = False

    if not user.get("is_local_token"):
        res = await db.execute(text("""SELECT MAX(CAST(g.is_superadmin AS INTEGER)), MAX(CAST(g.can_add AS INTEGER)), MAX(CAST(g.can_edit AS INTEGER)), MAX(CAST(g.can_delete AS INTEGER)) 
                     FROM groups g JOIN usergroups ug ON g.id = ug.group_id 
                     WHERE ug.user_id = :user_id AND g.is_deleted = False"""), {"user_id": user_id})
        row = res.fetchone()
        if not row or (not row[0] and not row[1] and not row[2] and not row[3]):
            await log_event(db, "Warning", user, request.client.host, "Unauthorized data submission attempt.")
            raise HTTPException(403, "No write permissions.")
        
        is_super, can_add, can_edit, can_delete = bool(row[0]), bool(row[1]), bool(row[2]), bool(row[3])
    else:
        is_super = can_add = can_edit = can_delete = True

    res = await db.execute(text("SELECT group_id FROM usergroups WHERE user_id = :user_id"), {"user_id": user_id})
    user_groups = [r[0] for r in res.fetchall()]

    processed_count = 0
    
    async with db_write_lock:
        async with db.begin():
            await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
            res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
            new_rev = res.scalar()

            for item in req.entities:
                deleted_at = datetime.now() if item.deleted else None
                
                res = await db.execute(text("SELECT 1 FROM entities WHERE id = :id"), {"id": item.id})
                exists = res.fetchone() is not None

                if not is_super:
                    if item.deleted and not can_delete: continue  
                    if exists and not item.deleted and not can_edit: continue 
                    if not exists and not can_add: continue 

                processed_count += 1
                if exists:
                    await db.execute(text("""UPDATE entities SET folder_id = :fid, encrypted_data = :data, revision = :rev, deleted = :del, deleted_at = :del_at WHERE id = :id"""), 
                                   {"fid": item.folder_id, "data": item.encrypted_data, "rev": new_rev, "del": item.deleted, "del_at": deleted_at, "id": item.id})
                else: 
                    await db.execute(text("""INSERT INTO entities (id, folder_id, encrypted_data, deleted, revision, deleted_at) VALUES (:id, :fid, :data, :del, :rev, :del_at)"""), 
                                   {"id": item.id, "fid": item.folder_id, "data": item.encrypted_data, "del": item.deleted, "rev": new_rev, "del_at": deleted_at})
                    if not item.folder_id:
                        for g in user_groups:
                            await db.execute(text("INSERT INTO entitypermissions (entity_id, group_id, access_level) VALUES (:eid, :gid, 'write') ON CONFLICT DO NOTHING"), {"eid": item.id, "gid": g})
            
            await log_event(db, "Data change", user, request.client.host, f"Successfully processed {processed_count} out of {len(req.entities)} objects.")

    accessible_ids_cache.clear() 
    await manager.broadcast({"event": "new_revision", "revision": new_rev})
    
    return {"status": "ok", "new_revision": new_rev, "conflicts": []}

@router.get("/deleted")
async def pull_deleted_entities(since_revision: int = 0, user = Depends(verify_user), db: AsyncSession = Depends(get_db)):
    user_id = get_user_id(user)
    
    res = await db.execute(text("SELECT is_approved FROM users WHERE id = :user_id"), {"user_id": user_id})
    row = res.fetchone()
    if not row or not row[0]: 
        return []

    res = await db.execute(text("SELECT id, revision FROM deletedentities WHERE revision > :rev"), {"rev": since_revision})
    rows = res.fetchall()
    
    return [{"id": r[0], "revision": r[1]} for r in rows]