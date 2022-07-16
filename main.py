"""Module with all window classes"""
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from hashlib import sha1
from install import install
from crypto import Crypto
from managers import AccountManager, CredenrialManager

class CredentialsTab:
    """Tab containing saved credentials"""
    def __init__(self, tab, user_id, crypto):
        self.user_id = user_id
        self.crypto = crypto
        self.tree = ttk.Treeview(
            tab,
            columns=('portal', 'login'),
            show='headings',
            height=8
        )
        self.get_data()
        self.configure_tree()
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

    def get_data(self):
        """
        method using CredentialManager
        to load credentials from data base and show them in app window
        """
        credentials=CredenrialManager(self.user_id).load_credentials()
        self.tree.delete(*self.tree.get_children())
        for credential in credentials:
            self.tree.insert(
                '',
                'end',
                values=(credential.portal, credential.login, credential.password)
            )
        self.tree.pack()

    def configure_tree(self):
        """tkinter tree configuration"""
        self.tree.heading('portal', text='portal')
        self.tree.heading('login', text='login')

    def on_select(self, event):
        """saving password selected from tree into clipboard"""
        [item] = self.tree.selection()
        selection = self.tree.item(item, 'values')
        self.coppy_to_clipboard(selection[2])

    def coppy_to_clipboard(self, encrypted_password):
        """clear clipboard and coppy param into it"""
        decrypted_password = self.crypto.decrypt(encrypted_password)
        self.tree.clipboard_clear()
        self.tree.clipboard_append(decrypted_password)

class AddPasswordTab:
    """Tab to save credentials"""
    def __init__(self, tab, credentials_tab,tab_system , user_id, crypto):
        self.tab_system = tab_system
        self.credentials_tab = credentials_tab
        self.user_id = user_id
        self.crypto = crypto
        portal_label = ttk.Label(tab,text='Portal')
        self.portal_entry = ttk.Entry(tab)

        login_label = ttk.Label(tab, text='Login')
        self.login_entry = ttk.Entry(tab)

        password_label = ttk.Label(tab,text='Password')
        self.password_entry = ttk.Entry(tab)

        add_password_button = ttk.Button(tab, text='Add Credentials!')
        add_password_button.bind('<Button-1>',self.on_click_add_password)

        portal_label.grid(row=0, column=0, padx=5)
        self.portal_entry.grid(row=0, column=1, pady=5)

        login_label.grid(row=1, column=0, padx=5)
        self.login_entry.grid(row=1, column=1, pady=5)

        password_label.grid(row=2, column=0, padx=5)
        self.password_entry.grid(row=2, column=1, pady=5)

        add_password_button.grid(row=3, column=0, columnspan=2)

    def on_click_add_password(self, event):
        """add password with button click"""
        self.add_credentials(
            self.portal_entry.get(),
            self.login_entry.get(),
            self.password_entry.get(),
        )

    def add_credentials(self, portal, login, password):
        """validate credentials and add them to database with CredentialsManager"""
        if len(portal) == 0 or len(login) == 0 or len(password) == 0:
            messagebox.showinfo('Message Box', 'Entry boxes cannot be empty!')
        else:
            encrypted_password = self.crypto.encrypt(password)
            CredenrialManager(self.user_id).add_credential(portal, login, encrypted_password)
            self.credentials_tab.get_data()
            self.tab_system.select(0)
            messagebox.showinfo('Message Box', 'Password Saved!')

class LoginWindow:
    """Launch window for logging in or creating a new account"""
    def __init__(self):
        self.master = tk.Tk()
        self.master.title('Password Manager')
        self.master.geometry('350x200')
        self.master.resizable(False, False)

        user_login_label = ttk.Label(text='Login')
        self.user_login_entry = ttk.Entry()

        user_password_label = ttk.Label(text='Password')
        self.user_password_entry = ttk.Entry(show='*')

        self.toggle_password_button = ttk.Button(self.master, text='Show Password', width=15)
        self.toggle_password_button.bind('<Button-1>',self.on_click_toggle_password)

        log_in_button = ttk.Button(self.master, text='Get in!', width=15)
        log_in_button.bind('<Button-1>',self.on_click_log_in)

        create_acc_button = ttk.Button(self.master, text='Create new account', width=20)
        create_acc_button.bind('<Button-1>',self.on_click_create_acc)

        user_login_label.grid(row=0, padx=40)
        self.user_login_entry.grid(row=1, pady=5)
        user_password_label.grid(row=2, padx=40)
        self.user_password_entry.grid(row=3, pady=5)
        self.toggle_password_button.grid(row=3, column=1, pady=5)
        log_in_button.grid(row=4, pady=5, padx=40)
        create_acc_button.grid(row=5, pady=5, padx=40)


    def on_click_log_in(self, event):
        """Login with button click method"""
        self.check_login_and_password(
            self.user_login_entry.get(),
            self.user_password_entry.get()
        )

    def check_login_and_password(self, user_login, user_password):
        """Check login and password and log in to the application"""
        if len(user_login) == 0 or len(user_password) == 0:
            messagebox.showinfo('Message Box', 'Login and Password cannot be empty!')
        elif sha1(user_password.encode('utf-8')).hexdigest().upper() == AccountManager(user_login, user_password).load_account().user_password:
            ApplicationWindow(
                self.master,
                AccountManager(user_login, user_password).load_account().user_id,
                AccountManager(user_login, user_password).load_account().user_password,
            )
            self.master.withdraw()
        else:
            messagebox.showinfo('Message Box', 'Uncorrect Login or Password!')

    def on_click_create_acc(self, event):
        """Create a new window for creating a new account"""
        NewAccWindow(self.master)


    def on_click_toggle_password(self, event):
        """Button to hide the entered password"""
        if self.user_password_entry.cget('show') == '':
            self.user_password_entry.config(show='*')
            self.toggle_password_button.config(text='Show Password')
        else:
            self.user_password_entry.config(show='')
            self.toggle_password_button.config(text='Hide Password')

    def run(self):
        """run app loop"""
        self.master.mainloop()

class ApplicationWindow:
    """App window with CredentialsTab and AddPasswordTab"""
    def __init__(self, parent, user_id, user_password):
        self.user_id = user_id
        self.parent = parent
        self.crpyto = Crypto(user_password)
        self.master = tk.Toplevel(self.parent)
        self.master.title('Password Manager')
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.tabsystem = ttk.Notebook(self.master)

        self.credentials_tab = tk.Frame(self.tabsystem)
        self.add_password_tab = tk.Frame(self.tabsystem)

        cred_tab = CredentialsTab(self.credentials_tab, self.user_id, self.crpyto)
        AddPasswordTab(
            self.add_password_tab,
            cred_tab,
            self.tabsystem,
            self.user_id,
            self.crpyto
        )

        self.create_tabs()

    def create_tabs(self):
        """add tabs to tabsystem and pack then into window"""
        self.tabsystem.add(self.credentials_tab, text='Credentials')
        self.tabsystem.add(self.add_password_tab, text='Add Passwrod')
        self.tabsystem.pack(expand=1, fill='both')

    def on_closing(self):
        """function to close the application with a cross button"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.parent.destroy()

class NewAccWindow:
    """Window for creating a new account"""
    def __init__(self, parent):
        self.master = tk.Toplevel(parent)
        self.master.title('Password Manager')
        self.master.geometry('350x200')
        self.master.resizable(False, False)

        user_login_label = ttk.Label(self.master, text='Login')
        self.user_login_entry = ttk.Entry(self.master)

        user_password_label = ttk.Label(self.master, text='Password')
        self.user_password_entry = ttk.Entry(self.master, show='*')

        user_repeat_password_label = ttk.Label(self.master, text='Repeat Password')
        self.user_repeat_password_entry = ttk.Entry(self.master, show='*')

        create_acc_button = ttk.Button(self.master, text='Create Account', width=15)
        create_acc_button.bind('<Button-1>',self.on_click_create_acc)

        user_login_label.grid(row=0, padx=40)
        self.user_login_entry.grid(row=1, pady=5)
        user_password_label.grid(row=2, column=0, padx=40)
        self.user_password_entry.grid(row=3, pady=5)
        user_repeat_password_label.grid(row=4, padx=40)
        self.user_repeat_password_entry.grid(row=5, pady=5)
        create_acc_button.grid(row=2, column=2)

    def on_click_create_acc(self, event):
        """Create ne account "on click" button method"""
        try:
            self.create_user(
                self.user_login_entry.get(),
                self.user_password_entry.get(),
                self.user_repeat_password_entry.get()
                )
        except TypeError:
            pass

    def create_user(self,user_login, user_password, user_repeated_password):
        """validate login and password, check if account already exists, create a new account"""
        dtoaccount = AccountManager(user_login, user_password).load_account()
        if len(user_login) == 0:
            messagebox.showinfo('Message Box', 'Login cannot be empty!')
        elif user_login == dtoaccount.user_login:
            messagebox.showinfo('Message Box', 'Login already taken! Choose another one!')
        else:
            if len(user_password) == 0:
                messagebox.showinfo('Message Box', 'Passowrd cannot be empty!')
            else:
                if user_password == user_repeated_password:
                    messagebox.showinfo('Message Box', 'Account Created')
                    hashed_user_password = sha1(user_password.encode('utf-8')).hexdigest().upper()
                    AccountManager(user_login, hashed_user_password).add_account()
                    self.master.destroy()
                else:
                    messagebox.showinfo('Message Box', 'Passwords are not the same!')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'install':
        install()
        sys.exit()
    root = LoginWindow()
    root.run()
