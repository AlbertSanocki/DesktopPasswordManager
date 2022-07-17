"""Tests for manager module"""
import pytest
from sqlalchemy import (
    create_engine,
    Table,
    Column,
    Integer,
    String,
    MetaData
    )
from managers import CredenrialManager, AccountManager, DTOCredentials
import managers

@pytest.fixture
def create_db():
    """
    Creating SQLite database in memory
    """
    engine = create_engine('sqlite:///:memory:', echo=True, future=True)
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
    return engine

def test_account_manager(create_db):
    """
    AccountManager test
    Adding a couple of accounts to account table
    next step is loading thoose accounts and check if:
    - they are DTOAccount objects
    - they have appropriate field values
    """
    AccountManager(create_db).add_account('TestLogin', 'Test Password')
    AccountManager(create_db).add_account('TestLogin2', 'Test Password2')
    AccountManager(create_db).add_account('TestLogin3', 'Test Password3')
    loaded_account = AccountManager(create_db).load_account('TestLogin', 'Test Password')
    loaded_account_three = AccountManager(create_db).load_account('TestLogin3', 'Test Password3')
    assert isinstance(loaded_account, managers.DTOAccount)
    assert loaded_account.user_id == 1
    assert loaded_account.user_login == 'TestLogin'
    assert loaded_account.user_password == 'Test Password'
    assert isinstance(loaded_account_three, managers.DTOAccount)
    assert loaded_account_three.user_id == 3
    assert loaded_account_three.user_login == 'TestLogin3'
    assert loaded_account_three.user_password == 'Test Password3'

def test_credential_manager(create_db):
    """
    CredentialManager test
    Adding a couple of accounts to credentials table
    next step is loading thoose credentials and check if:
    - they are list of DTOCredential objects
    - they have appropriate field values
    """
    CredenrialManager(create_db, 1).add_credential('ID1Portal1','ID1Login1','ID1Password1')
    CredenrialManager(create_db, 1).add_credential('ID1Portal2','ID1Login2','ID1Password2')
    CredenrialManager(create_db, 1).add_credential('ID1Portal3','ID1Login3','ID1Password3')
    CredenrialManager(create_db, 2).add_credential('ID2Portal1','ID2Login1','ID2Password1')
    CredenrialManager(create_db, 2).add_credential('ID2Portal2','ID2Login2','ID2Password2')
    CredenrialManager(create_db, 3).add_credential('ID3Portal1','ID3Login1','ID3Password1')
    CredenrialManager(create_db, 3).add_credential('ID3Portal2','ID3Login2','ID3Password2')

    loaded_credentials_1_id = CredenrialManager(create_db, 1).load_credentials()
    loaded_credentials_2_id = CredenrialManager(create_db, 2).load_credentials()
    loaded_credentials_3_id = CredenrialManager(create_db, 3).load_credentials()

    assert isinstance(loaded_credentials_1_id, list)
    assert isinstance(loaded_credentials_2_id, list)
    assert isinstance(loaded_credentials_3_id, list)
    assert len(loaded_credentials_1_id) == 3
    assert loaded_credentials_1_id == [
        DTOCredentials(portal='ID1Portal1', login='ID1Login1', password='ID1Password1'),
        DTOCredentials(portal='ID1Portal2', login='ID1Login2', password='ID1Password2'),
        DTOCredentials(portal='ID1Portal3', login='ID1Login3', password='ID1Password3')
        ]
    assert loaded_credentials_3_id == [
        DTOCredentials(portal='ID3Portal1', login='ID3Login1', password='ID3Password1'),
        DTOCredentials(portal='ID3Portal2', login='ID3Login2', password='ID3Password2')
        ]
