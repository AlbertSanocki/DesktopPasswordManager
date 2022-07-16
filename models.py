"""Models to support tables in the database"""
from sqlalchemy.orm import declarative_base, relationship, backref
from sqlalchemy import Integer, Column, String, create_engine, ForeignKey

engine = create_engine('sqlite:///database.db', echo=True, future=True)
Base = declarative_base()

class Account(Base):
    """Account class to service account table in database"""
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    user_login = Column(String(50))
    user_password = Column(String(100))

class Credential(Base):
    """Credential class to service credentials table in database"""
    __tablename__='credentials'
    id = Column(Integer, primary_key=True)
    portal = Column(String(50))
    login = Column(String(50))
    password = Column(String(100))
    account_id = Column(Integer, ForeignKey('accounts.id'))
    account = relationship('Account', backref=backref('credentials', uselist=False))
