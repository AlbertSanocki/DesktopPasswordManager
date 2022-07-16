# DesktopPasswordManager

Desktop app for storing passwords.

Application can be used by many users on one computer. You can create as many accounts as you want. 
Creating an account is child's play.

Press "Create new account"

![image](https://user-images.githubusercontent.com/100367053/179363554-e40edb8b-a1a4-4f46-a29d-eea86c8a048a.png)

Type Your login and password and press "Create Account"

![image](https://user-images.githubusercontent.com/100367053/179363612-1cbf9987-6a1e-46c7-bf99-02f705965cf3.png)

Remember that passwords must be the same! If otherwise, you will see the following message:

![image](https://user-images.githubusercontent.com/100367053/179363629-46768e81-180a-4876-ab32-88228888f391.png)

If everything goes well You should see the following message:

![image](https://user-images.githubusercontent.com/100367053/179363662-5ec70a11-0c1b-43d3-a777-3bbd6c8db7de.png)

Now You can log in to application

![image](https://user-images.githubusercontent.com/100367053/179363757-ffba3990-c6b1-496e-a6b8-3603bcfd4aa8.png)

Once logged in, the program window will appear:

![image](https://user-images.githubusercontent.com/100367053/179362848-f3067455-0ecf-4701-b593-5d33e9f6a3a6.png)

The table is empty because You haven't added any password yet. Lets do this!
Go to the "Add password" tab, enter the portal, login and password. Then click on the button "Add credentials!"

![image](https://user-images.githubusercontent.com/100367053/179363134-3d486066-4dbc-4ede-b44a-45ecdfdf4c3a.png)

Password Saved!

![image](https://user-images.githubusercontent.com/100367053/179363200-7de92cc8-ddbe-43c7-97a2-5ba4bb1c609b.png)

Now you can copy the saved password to clipboard by selecting the row containing the data you are interested in!

![image](https://user-images.githubusercontent.com/100367053/179363398-61f00508-66ab-462e-9475-b6675b90bc0b.png)
 
 And paste it to password entry on the portal you are using.
 
The account password stored in the database has been hashed.

Passwords kept in the database are encrypted with cryptography Fernet. The fernet key is made of a hashed account password.
