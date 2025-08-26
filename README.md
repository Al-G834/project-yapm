# Yet Another Password Manager

## Video Demo: <url>

### Description:

<img width="520" height="457" alt="yapm" src="https://github.com/user-attachments/assets/22f579f9-94ab-4033-a500-e2cd96f26bf8" />


My final project is a password manager that stores the username and password in a nested dictionary. This would be an example:

```json
{ "Sample Site ID": { "username": "Ur Name", "password": "gAAAAABocrKA8CaFGJxIWTnFBeBz2ybHzYGP6kJhCl24OarLtw8SdJfvWCNiOE4HN1QFVpgbOuLHPVCTqEvfGdOcXdGRWvWfqZvZImT4onSPtmYGrGem9ww=" }, 
```

I wanted to use Tkinter to get familiar with GUI interfaces.  I also chose to us the PyPi Python package cryptography.

```bash
pip install cryptography
```

The directory structure is described by this figure:
```bash
[drwxrwxr-x]  .
├── [-rw-rw-r--]  password.json
├── [-rw-rw-r--]  project.py
└── [drwxr-----]  .projectrc
    └── [-rwx------]  encryption_key.key
```

**Initial Startup**  
When the ```project.py``` is started, it check to see if the hidden directory, .projectrc, exists.  If this is the first time, the hidden directory is created and the encryption key is written in that .projectrc directory.  A sample Site ID, userid, and password are written to the password file.  
The encryption key is used to encrypt/decrypt the stored password.  If the key is erased, a new one will be generated.  But all of the stored passwords will be useless.  
Messages will be displayed in the text widget, error messages are displayed in red.

The application provides five functions to manage the dictionary:  
        1. Add  
        2. Get  
        3. List  
        4. Update  
        5. Delete  

Each function begins by reading the password.json file into memory. At the end of each function, the nested dictionary is serialized into a json formatted file and written to disk.  
The dictionary allows only one username-password tuple per Identifier/Site ID.  

**1. Add Processing**  
Populate the SITE ID, USERNAME, and PASSWORD widgets.  
Pressing the 'Add' button causes the app to check if the Site ID already exists, if it does and error message is displayed in the Text frame below. If the Site ID does not exist in the dictionary, the password is checked for the following:  
- the password must be longer than 7 characters.   
- the password must be shorter than 21 characters.   
- the password must contain at least one upper-case character.   
- the password must contain at least one lower-case character.   
- the password must contain at least one digit.  
- the password must contain at least one special character from the list '@$!%*?&'.   
- the password cannot contain embedded spaces.  

After the password has been encrypted, the dictionary is updated and written to a json file.  

**2. Get processing**  
Populate the SITE ID widget.  
Press the Get button, the application will locate and display the SITE ID, USERNAME, and PASSWORD in the Text frame. The password will be displayed in plain-text.

**3. List processing**  
The widgets may be left blank.
Press the List button and all SITE ID's will be displayed in the Text widget.

**4. Update processing**  
Populate the SITE ID and PASSWORD widgets.
Only the SITE ID and PASSWORD are required to update the password. The value of the password is replaced with the encrypted password.

**5. Delete processing**  
Populate the SITE ID.  
The SITE ID, USERNAME, and PASSWORD will be deleted from the dictionary.
