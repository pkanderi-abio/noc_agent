import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agent.db import Base, User, Role, init_db
from agent.config import Config

# Use in-memory SQLite for testing
en = create_engine('sqlite:///:memory:')
TestingSessionLocal = sessionmaker(bind=en)
Base.metadata.create_all(en)

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    # Override engine and session in db module
    monkeypatch.setattr('agent.db.engine', en)
    monkeypatch.setattr('agent.db.SessionLocal', TestingSessionLocal)
    # create tables and defaults
    init_db()
    return TestingSessionLocal()

def test_create_and_delete_user(setup_db):
    db = setup_db
    # create new user via db
    from agent.db import Role
    # ensure role exists
    r = db.query(Role).first()
    # create
    from user_management import create_user
    create_user(db, 'testuser', 'pass', [r.name])
    user = db.query(User).filter_by(username='testuser').first()
    assert user is not None
    # delete
    from user_management import delete_user
    delete_user(db, 'testuser')
    assert db.query(User).filter_by(username='testuser').first() is None

def test_reset_password(setup_db):
    db = setup_db
    # use initial user
    from user_management import reset_password
    reset_password(db, 'admin', 'newpass')
    user = db.query(User).filter_by(username='admin').first()
    # test password changed
    from passlib.context import CryptContext
    ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    assert ctx.verify('newpass', user.hashed_password)

def test_update_roles(setup_db):
    db = setup_db
    from user_management import update_roles
    # create a 'user' role if not exists
    from agent.db import Role
    role_user = db.query(Role).filter_by(name='user').first()
    update_roles(db, 'admin', ['user'])
    user = db.query(User).filter_by(username='admin').first()
    assert 'user' in [r.name for r in user.roles]