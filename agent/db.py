from sqlalchemy import Column, String, Integer, Table, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agent.config import Config
from passlib.context import CryptContext

# place this right after your imports
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()
################################################################
# Association table
user_roles = Table(
    'user_roles', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    roles = relationship('Role', secondary=user_roles, back_populates='users')

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    users = relationship('User', secondary=user_roles, back_populates='roles')

# DB engine and session
cfg = Config.load()
engine = create_engine(cfg.database.get('url'), connect_args={
    'check_same_thread': False
} if 'sqlite' in cfg.database.get('url') else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Initialize DB (called at startup)
def init_db():
    Base.metadata.create_all(bind=engine)
    # create default roles and users
    from agent.config import Config
    cfg = Config.load()
    db = SessionLocal()
    for role_name in cfg.rbac.get('roles', {}):
        if not db.query(Role).filter_by(name=role_name).first():
            db.add(Role(name=role_name))
    db.commit()
    # initial users
    for u in cfg.auth_defaults.get('initial_users', []):
        if not db.query(User).filter_by(username=u['username']).first():
            hashed = pwd_context.hash(u['password'])
            user = User(username=u['username'], hashed_password=hashed)
            for role_name in u['roles']:
                role = db.query(Role).filter_by(name=role_name).first()
                user.roles.append(role)
            db.add(user)
    db.commit()
    db.close()