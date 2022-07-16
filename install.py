"""install module allows to create a database at program start if the database does not exist yet"""
from sqlalchemy import (
    create_engine,
    Table,
    Column,
    Integer,
    String,
    MetaData
    )

def install():
    """install function creates a database if it does not already exist"""
    engine = create_engine('sqlite:///database.db', echo=True, future=True)
    meta = MetaData()
    accounts = Table(
        'accounts', meta,
        Column('id', Integer, primary_key=True),
        Column('user_login', String),
        Column('user_password', String),
    )

    credentials = Table(
        'credentials', meta,
        Column('id', Integer, primary_key=True),
        Column('portal', String),
        Column('login', String),
        Column('password', String),
        Column('account_id', Integer)
    )
    meta.create_all(engine)
