from sqlalchemy import Column, String, Integer, Table, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agent.config import Config
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base = declarative_base()

user_roles = Table(
    'user_roles', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    _hashed_password = Column(String, name='hashed_password')
    roles = relationship('Role', secondary=user_roles, back_populates='users')

    @property
    def hashed_password(self):
        return self._hashed_password

    @hashed_password.setter
    def hashed_password(self, value):
        self._hashed_password = value

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    users = relationship('User', secondary=user_roles, back_populates='roles')

cfg = Config.load()
engine = create_engine(cfg.database.get('url'), connect_args={
    'check_same_thread': False
} if 'sqlite' in cfg.database.get('url') else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    cfg = Config.load()
    db = SessionLocal()
    # Create all roles, including sub-roles
    all_roles = set()
    for role_name, sub_roles in cfg.rbac.get('roles', {}).items():
        all_roles.add(role_name)
        all_roles.update(sub_roles)
    for role_name in all_roles:
        if not db.query(Role).filter_by(name=role_name).first():
            db.add(Role(name=role_name))
    db.commit()
    # Create initial users
    for u in cfg.auth_defaults.get('initial_users', []):
        if not db.query(User).filter_by(username=u['username']).first():
            hashed = pwd_context.hash(u['password'])
            user = User(username=u['username'], hashed_password=hashed)
            # Assign roles, including sub-roles for admin
            user_roles = set(u['roles'])
            if 'admin' in u['roles']:
                user_roles.update(cfg.rbac.get('roles', {}).get('admin', []))
            for role_name in user_roles:
                role = db.query(Role).filter_by(name=role_name).first()
                if role:
                    user.roles.append(role)
            db.add(user)
    db.commit()
    db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()  
# Initialize the database if it hasn't been done yet
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
# This module initializes the database and defines the ORM models for users and roles.