from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import asyncio

audit_lock = asyncio.Lock()

def get_user_id(user: dict):
    if user.get("is_local_token"): return user.get("email")
    uname = user.get("username", "").strip()
    if uname: return uname
    email = user.get("email", "").strip()
    if email: return email
    return "UnknownUser"

async def log_event(db: AsyncSession, event_type: str, user: dict, ip: str, details: str):
    async with audit_lock:
        username = user.get("username", "Unknown")
        email = user.get("email", "")
        await db.execute(text("INSERT INTO auditlog (event_type, username, email, ip_address, details) VALUES (:et, :un, :em, :ip, :dt)"), 
                       {"et": event_type, "un": username, "em": email, "ip": ip, "dt": details})
        await db.commit()