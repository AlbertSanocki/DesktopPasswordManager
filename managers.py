"""managers module allows to add and download data from database"""
from dataclasses import dataclass
from sqlalchemy.orm import Session
from models import Account, Credential, engine

@dataclass
class DTOAccount:
    """Account data transfer object class"""
    user_id: int
    user_login: str
    user_password: str

@dataclass
class DTOCredentials:
    """Credentials data transfer object class"""
    portal: str
    login: str
    password: str

class AccountManager:
    """
    AccountManager class allows to add new accounts to database
    and load existing ones
    """
    def __init__(self, user_login, user_password):
        self.user_login = user_login
        self.user_password = user_password

    def add_account(self):
        """Add new account to database"""
        with Session(engine) as session:
            user_account = Account(user_login=self.user_login, user_password=self.user_password)
            session.add_all([user_account])
            session.commit()

    def load_account(self):
        """
        Load existing account from database.
        Returns filled DTOAccount object if account exists
        or empty DTOAccount object if the account does not exist
        """
        try:
            with Session(engine) as session:
                [user_id] = [account.id for account in session.query(Account).filter(Account.user_login==self.user_login)]
                [user_login] = [account.user_login for account in session.query(Account).filter(Account.user_login==self.user_login)]
                [user_password] = [account.user_password for account in session.query(Account).filter(Account.user_login==self.user_login)]

            return DTOAccount(
                user_id,
                user_login,
                user_password,
            )
        except ValueError:
            return DTOAccount(
                None,
                None,
                None,
            )

class CredenrialManager:
    """
    CredentialManager class allows to add new credentials to database
    and load existing ones
    """
    def __init__(self, account_id):
        self.account_id = account_id

    def add_credential(self, portal, login, password):
        """Add credentials assigned to given account_id to the database"""
        with Session(engine) as session:
            credential = Credential(
                portal=portal,
                login=login,
                password=password,
                account_id=self.account_id
            )
            session.add_all([credential])
            session.commit()

    def load_credentials(self):
        """
        Loading credentials.
        Returns list of DTOCredentials objects
        """
        with Session(engine) as session:
            credentials = []
            for credential in session.query(Credential).filter(Credential.account_id==self.account_id):
                portal = credential.portal
                login = credential.login
                password = credential.password

                dto_credentials = DTOCredentials(
                    portal,
                    login,
                    password,
                )
                credentials.append(dto_credentials)
            return credentials
