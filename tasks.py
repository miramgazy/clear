import asyncio
from sqlalchemy import text
from database import AsyncSessionLocal as async_session_maker
from ws_router import manager

async def background_cleanup_task():
    while True:
        try:
            async with async_session_maker() as db:
                res = await db.execute(text("SELECT value FROM serversettings WHERE key = 'DeletedRetentionDays'"))
                row = res.fetchone()
                retention_days = int(row[0]) if row else 30

                cleanup_query = text(f"""
                    SELECT id FROM entities 
                    WHERE deleted = True 
                    AND deleted_at IS NOT NULL 
                    AND deleted_at < now() - interval '{retention_days} days'
                """)
                res = await db.execute(cleanup_query)
                to_delete = [r[0] for r in res.fetchall()]

                if to_delete:
                    await db.execute(text("UPDATE dbversion SET revision = revision + 1"))
                    res = await db.execute(text("SELECT revision FROM dbversion LIMIT 1"))
                    new_rev = res.scalar()

                    for entity_id in to_delete:
                        await db.execute(text("INSERT INTO deletedentities (id, revision) VALUES (:id, :rev) ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision"), 
                                       {"id": entity_id, "rev": new_rev})
                        await db.execute(text("DELETE FROM entities WHERE id = :id"), {"id": entity_id})
                        await db.execute(text("DELETE FROM entitypermissions WHERE entity_id = :id"), {"id": entity_id})

                    await db.commit()
                    await manager.broadcast({"event": "new_revision", "revision": new_rev})
                    print(f"[CLEANUP] Permanently deleted old records: {len(to_delete)}.")

                res = await db.execute(text("SELECT value FROM serversettings WHERE key = 'AuditRetentionDays'"))
                audit_row = res.fetchone()
                audit_retention = int(audit_row[0]) if audit_row else 90

                res = await db.execute(text(f"DELETE FROM auditlog WHERE timestamp < now() - interval '{audit_retention} days'"))
                if res.rowcount > 0:
                    print(f"[CLEANUP] Deleted old audit log entries: {res.rowcount}")
                
                await db.commit()

        except Exception as e:
            print(f"[CLEANUP ERROR] Error during DB cleanup: {e}")

        await asyncio.sleep(3600)