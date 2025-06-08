#!/usr/bin/env python3
import argparse
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from agent.db import SessionLocal, User, Role

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_user(db: Session, username: str, password: str, roles: list[str]):
    hashed = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed)
    for r in roles:
        role = db.query(Role).filter_by(name=r).first()
        if role:
            user.roles.append(role)
    db.add(user)
    db.commit()
    print(f"User '{username}' created.")

def delete_user(db: Session, username: str):
    user = db.query(User).filter_by(username=username).first()
    if not user:
        print("User not found.")
        return
    db.delete(user)
    db.commit()
    print(f"User '{username}' deleted.")

def reset_password(db: Session, username: str, new_password: str):
    user = db.query(User).filter_by(username=username).first()
    if not user:
        print("User not found.")
        return
    user.hashed_password = pwd_context.hash(new_password)
    db.commit()
    print(f"Password for '{username}' reset.")

def update_roles(db: Session, username: str, roles: list[str]):
    user = db.query(User).filter_by(username=username).first()
    if not user:
        print("User not found.")
        return
    user.roles.clear()
    for r in roles:
        role = db.query(Role).filter_by(name=r).first()
        if role:
            user.roles.append(role)
    db.commit()
    print(f"Roles for '{username}' updated to {roles}.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="User management CLI")
    sub = parser.add_subparsers(dest='cmd')

    # create
    p1 = sub.add_parser('create')
    p1.add_argument('username')
    p1.add_argument('password')
    p1.add_argument('--roles', nargs='+', default=['user'])

    # delete
    p2 = sub.add_parser('delete')
    p2.add_argument('username')

    # reset-password
    p3 = sub.add_parser('reset-password')
    p3.add_argument('username')
    p3.add_argument('new_password')

    # update-roles
    p4 = sub.add_parser('update-roles')
    p4.add_argument('username')
    p4.add_argument('--roles', nargs='+', required=True)

    args = parser.parse_args()
    db = SessionLocal()
    if args.cmd == 'create':
        create_user(db, args.username, args.password, args.roles)
    elif args.cmd == 'delete':
        delete_user(db, args.username)
    elif args.cmd == 'reset-password':
        reset_password(db, args.username, args.new_password)
    elif args.cmd == 'update-roles':
        update_roles(db, args.username, args.roles)
    else:
        parser.print_help()
    db.close()