import secrets
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, select
from config import DATABASE_URL
from models_db import Base, Group, ServerSetting, DbVersion

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def init_db():
    async with engine.begin() as conn:
        # Create all tables if they don't exist
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Check and initialize default groups
        result = await session.execute(select(Group).filter_by(id='admin_group'))
        if not result.scalar_one_or_none():
            admin_group = Group(id='admin_group', name='Администратор', is_superadmin=True)
            moder_group = Group(id='moder_group', name='Модератор', can_add=True, can_edit=True, can_delete=True, can_manage_users=True)
            user_group = Group(id='user_group', name='Пользователь', can_add=True, can_edit=True)
            new_user_group = Group(id='new_user_group', name='Новый пользователь')
            no_rights_group = Group(id='no_rights_group', name='Без прав', is_hidden=True)
            
            session.add_all([admin_group, moder_group, user_group, new_user_group, no_rights_group])
            
            settings = [
                ServerSetting(key='AuditRetentionDays', value='90'),
                ServerSetting(key='DeletedRetentionDays', value='30'),
                ServerSetting(key='DefaultGroupId', value='new_user_group')
            ]
            session.add_all(settings)
            
            # Init DbVersion
            db_rev = DbVersion(revision=0, admin_revision=0)
            session.add(db_rev)

        # Check and initialize MasterKey
        result = await session.execute(select(ServerSetting).filter_by(key='MasterKey'))
        if not result.scalar_one_or_none():
            master_key = secrets.token_urlsafe(32)
            session.add(ServerSetting(key='MasterKey', value=master_key))
            
        await session.commit()