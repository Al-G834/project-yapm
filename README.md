# Yet Another Password Manager

## Video Demo: <url>

### Description:

[yapm screenshot](https://github.com/Al-G834/project-yapm/yapm.png)



My project is a password manager that stores the username and password in a nested dictionary. This would be an example:

```
{ "Sample Site ID": { "username": "Ur Name", "password": "gAAAAABocrKA8CaFGJxIWTnFBeBz2ybHzYGP6kJhCl24OarLtw8SdJfvWCNiOE4HN1QFVpgbOuLHPVCTqEvfGdOcXdGRWvWfqZvZImT4onSPtmYGrGem9ww=" }, 
```

This project could have been written as a CLI application. I also chose to use the cryptography module.

```
pip install cryptography
```

The application provides five functions:  
        1. Add  
        2. Get  
        3. List  
        4. Update  
        5. Delete  

Each function begins by reading the password.json file into memory. At the end of the function, the nested dictionary is serialized into a json formatted file and written to disk.  
The dictionary allows only one username-password tuple per Identifier/Site ID. When adding a Site ID for the first time, it is necessary populate the Site ID, username, and password.  Pressing the 'Add' button causes the app to check if the Site ID already exists, if it does and error message is displayed in the Text frame below. If the Site ID does not exist in the dictionary, the password is checked for the following:  
        - the password must be longer than 7 characters.   
        - the password must be shorter than 21 characters.   
        - the password must contain at least one upper-case character.   
        - the password must contain at least one lower-case character.   
        - the password must contain at least one special character from the list '@$!%*?&'.   
        - the password must contain at least one digit.  
        - the password cannot contain embedded spaces.  
After the password has been encrypted, the dictionary is updated and written to file.  

**Get processing**  
Populating the Site ID and pressing the Get button will cause the application to locate and display the Site ID, username, and password in the Text frame. The password will be displayed in plain-text.

**List processing**  
Pressing the List button will list the Site IDs in the Text frame.

**Update processing**  
Only the Site ID and password are required to update the password. The value of the password is replaced with the encrypted password.

**Delete processing**  
The Site ID is required to delete the username and password.
