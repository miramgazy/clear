from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, PrimaryKeyConstraint, ForeignKey
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql import func

class Base(DeclarativeBase):
    pass

class DbVersion(Base):
    __tablename__ = "dbversion"
    revision = Column(Integer, primary_key=True, default=0)
    admin_revision = Column(Integer, default=0)

class Entity(Base):
    __tablename__ = "entities"
    id = Column(String, primary_key=True)
    folder_id = Column(String, default="")
    encrypted_data = Column(Text)
    deleted = Column(Boolean, default=False)
    revision = Column(Integer)
    deleted_at = Column(DateTime)

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String)
    email = Column(String)
    first_connect = Column(DateTime, server_default=func.now())
    last_connect = Column(DateTime, server_default=func.now(), onupdate=func.now())
    is_approved = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

class LocalToken(Base):
    __tablename__ = "localtokens"
    id = Column(String, primary_key=True)
    token_hash = Column(String)
    description = Column(String)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    is_active = Column(Boolean, default=True)

class Group(Base):
    __tablename__ = "groups"
    id = Column(String, primary_key=True)
    name = Column(String)
    is_superadmin = Column(Boolean, default=False)
    can_manage_users = Column(Boolean, default=False)
    can_save_local = Column(Boolean, default=False)
    can_add = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    can_read_log = Column(Boolean, default=False)
    can_manage_roles = Column(Boolean, default=False)
    can_manage_settings = Column(Boolean, default=False)
    is_hidden = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)

class UserGroup(Base):
    __tablename__ = "usergroups"
    user_id = Column(String)
    group_id = Column(String)
    __table_args__ = (
        PrimaryKeyConstraint("user_id", "group_id"),
    )

class EntityPermission(Base):
    __tablename__ = "entitypermissions"
    entity_id = Column(String)
    group_id = Column(String)
    access_level = Column(String)
    __table_args__ = (
        PrimaryKeyConstraint("entity_id", "group_id"),
    )

class ServerSetting(Base):
    __tablename__ = "serversettings"
    key = Column(String, primary_key=True)
    value = Column(Text)

class AuditLog(Base):
    __tablename__ = "auditlog"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now())
    event_type = Column(String)
    username = Column(String)
    email = Column(String)
    ip_address = Column(String)
    details = Column(Text)

class DeletedEntity(Base):
    __tablename__ = "deletedentities"
    id = Column(String, primary_key=True)
    revision = Column(Integer)
