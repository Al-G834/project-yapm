"""
    Yet Another Password Manager implements a password manager with
    the ability to:
        - add
        - update
        - delete
        - list
        - get
        passwords
    The passwords are stored as a nested dictionary.
"""
import os
import sys
import hashlib
import json
import re

import tkinter as tk
from tkinter.font import Font
from tkinter import Menu

from cryptography.fernet import Fernet


def create_rc_dir():
    """Create a ~/.projectrc directory in the directory that the script
    was invoked in.  This hidden directory is used to store the
    encryption key used to encrypt/decrypt the password.
    """
    if not os.path.isdir(".projectrc"):
        os.mkdir("./.projectrc", mode=0o740)


def hash_pwd(password):
    """hash the password using sha256, returns hashed passwork"""
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()


def generate_key():
    """generate a secret key.  only done once."""
    return Fernet.generate_key()


def init_cipher(key):
    """initialize the fernet cipher"""
    return Fernet(key)


def encrypt_pwd(cipher, password):
    """the password is encoded using the cipher"""
    return cipher.encrypt(password.encode()).decode()


def decrypt_pwd(cipher, encrypted_pwd):
    """the password is decrypted using the cipher"""
    return cipher.decrypt(encrypted_pwd.encode()).decode()


def load_encryption_key():
    """The encryption_key is generated and stored
    in a hidden directory, ./projectrc.
    The encryption_key will be used repeatedly to
    hash passwords stored in the file.
    """
    key_flnm = ".projectrc/encryption_key.key"
    if os.path.exists(key_flnm):
        with open(key_flnm, "rb") as key_file:
            key = key_file.read()
    else:
        key = generate_key()
        with open(key_flnm, "wb") as key_file:
            key_file.write(key)

    os.chmod(key_flnm, 0o700)
    cipher = init_cipher(key)
    return cipher


def read_file(json_file="password.json"):
    """open the password file"""
    password_file = json_file
    password_dict = {}
    try:
        with open(password_file, "r", encoding="utf-8") as password_dict_fh:
            password_dict = json.load(password_dict_fh)
    except FileNotFoundError as e_fnf:
        raise FileNotFoundError("File password.json not found") from e_fnf
    except json.JSONDecodeError as decode_err:
        # print(f"Invalid JSON syntax")
        raise json.decoder.JSONDecodeError(
            "Invalid JSON syntax", "password file", 0
        ) from decode_err
    except AttributeError as attr_err:
        sys.exit(f"{attr_err}")
    return password_dict


def write_file(password_dict, json_file="password.json"):
    """close the password file"""
    password_file = json_file
    if validate_json(f'"{password_dict}"') is True:
        with open(password_file, "w", encoding="utf-8") as password_fh:
            json.dump(password_dict, password_fh)


def write_file_exit():
    """Exit"""
    sys.exit(0)


def validate_json(json_data):
    """The json dictionary is validated."""
    try:
        json.loads(json_data)
        return True
    except ValueError:
        return False


def add(event):
    """Add the nested dictionary to the SiteID dictionary"""
    password_dict = read_file()

    site_id = entry_site.get().strip()
    username = entry_name.get().strip()
    password = entry_password.get().strip()
    if not validate_pwd(password):
        msg = "Password must have at least:\none upper-case letter,\n"
        msg += "one lower-case letter,\n"
        msg += "1 digit,\n"
        msg += "a special character '@$!%*?&',\n"
        msg += "no embeded spaces,\n"
        msg += "and the length must be 8 characters or longer"
        msg += f"\n{password}"
        msg_type = "warning"
    else:
        key_list = list(password_dict.keys())
        if site_id in key_list:
            msg = "Error: The site_id already exists in passwords"
            msg_type = "warning"
        elif site_id and username and password:
            password_dict = add_password(password_dict, site_id, 
                    username, password)
            write_file(password_dict)
            msg = "Success, Password added!!"
            msg_type = "normal"
        else:
            msg = "Error: Please enter all the fields"
            msg_type = "warning"

    clear_entry_widgets()
    show_msg(msg, msg_type)


def add_password(password_dict, site_id, username, password):
    """The password for the Site ID is updated."""

    password_dict = {
        **password_dict,
        site_id: {
            "username": username,
            "password": f"{encrypt_pwd(cipher, password)}",
        },
    }
    return password_dict


def update(event):
    """update the password for the Site ID and username"""
    password_dict = read_file()

    site = entry_site.get().strip()
    password = entry_password.get().strip()
    clear_entry_widgets()
    if not validate_pwd(password):
        msg = "Password must have at least:\none upper-case letter,\n"
        msg += "one lower-case letter,\n"
        msg += "1 digit,\n"
        msg += "a special character '@$!%*?&',\n"
        msg += "no embeded spaces,\n"
        msg += "and the length must be 8 characters or longer"
        msg += f"\n{password}"
        msg_type = "warning"
    else:
        password_dict = update_password(site, password, password_dict)
        msg = f"Site ID: {site} updated!!"
        msg_type = "normal"
        write_file(password_dict)

    show_msg(msg, msg_type)


def update_password(site, password, password_dict):
    """The password for the given site is updated."""
    try:
        password_dict[f"{site}"].update(
            {"password": f"{encrypt_pwd(cipher, password)}"}
        )
    except KeyError as key_err:
        sys.exit(f"{key_err}")
    except ValueError as json_error:
        sys.exit(f"Error decoding JSON: {json_error}")

    return password_dict


def get(event):
    """get the username and password for the Site ID"""
    password_dict = read_file()

    site = entry_site.get().strip()
    clear_entry_widgets()

    if site in password_dict.keys():
        for site_id, info in password_dict.items():
            if site != site_id:
                continue
            msg = f"Site ID: {site_id}"
            for key, value in info.items():
                if key == "password":
                    msg += f"\n{key}: {decrypt_pwd(cipher, value)}"
                else:
                    msg += f"\n{key}: {info[key]}"

        msg_type = "normal"
    else:
        msg = f"Site ID '{site}' not found!!"
        msg_type = "warning"

    show_msg(msg, msg_type)


def getlist(event):
    """list all Site ID's in the dictionary"""
    password_dict = read_file()

    clear_entry_widgets()
    if password_dict is not None:
        msg = "List of saved sites:\n"
        for site_id in password_dict.keys():
            msg += f"Site ID: {site_id}\n"
        msg_type = "normal"
    else:
        msg = "Empty password file!!"
        msg_type = "warning"

    show_msg(msg, msg_type)


def delete(event):
    """delete the Site ID"""
    password_dict = read_file()

    site_id = entry_site.get().strip()
    clear_entry_widgets()
    if site_id:
        deleted_site = password_dict.pop(site_id, None)
        if deleted_site is None:
            msg = "SiteID not found"
            msg_type = "warning"
        else:
            msg = f"SiteID: {site_id} deleted"
            msg_type = "normal"
    else:
        msg = "Please provide Site ID"
        msg_type = "warning"

    write_file(password_dict)
    show_msg(msg, msg_type)
    clear_entry_widgets()


def load_initial_json_file(cipher):
    """If the password file does not exist, then load a sample
    and create the password.json file.
    """
    if not os.path.isfile("./password.json"):
        sample_password = "UseAMixedCasePwd@1"
        encrypted_sample = encrypt_pwd(cipher, sample_password)
        sample_dictionary = {
            "Sample Site ID": {"username": "Ur Name", "password": f"{encrypted_sample}"}
        }
        with open("password.json", "w", encoding="utf-8") as outfile:
            json.dump(sample_dictionary, outfile)


def validate_pwd(password):
    """Validates the enterred password, must have:
    - at least one lower-case letter
    - at least one upper-case letter
    - at least one digit, 0-9
    - at least one special character from the list @$!%*#?&
    - the length must be at least 8 characters and a maximum of 20
    """
    pattern = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d[@$!%*#?&]{8,20}$"
    )

    remat = re.fullmatch(pattern, password)
    return bool(remat)


def clear_entry_widgets():
    """Clears the entry wigets for Site ID, username, and password."""
    entry_site.delete(0, tk.END)
    entry_name.delete(0, tk.END)
    entry_password.delete(0, tk.END)


def clear_fields():
    """clear the widgets of left-over values"""
    entry_site.delete(0, "end")
    entry_name.delete(0, "end")
    entry_password.delete(0, "end")
    T["state"] = "normal"
    T.delete("1.0", tk.END)
    T["state"] = "disabled"


def show_msg(msg, msg_type):
    """display message"""
    # Clear the widget
    T["state"] = "normal"
    T.delete("1.0", tk.END)
    # Showing the msgage
    T.insert("end", msg, msg_type)
    T["state"] = "disabled"


def add_help():
    """display add help hints"""
    msg = "To add an item to the Passord Manager, populate the widgets:\n"
    msg += "Site ID\nUsername\nPassword"
    show_msg(msg, "normal")


def get_help():
    """display get help"""
    msg = "If the Site ID is in the password file, the Site ID, Username, "
    msg += "and Password will be displayed."
    show_msg(msg, "normal")


def list_help():
    """help message regarding the list function"""
    msg = "List will display all Site ID's in the password file."
    show_msg(msg, "normal")


def update_help():
    """help message regarding the update of the password for a Site ID"""
    msg = "This function will update the password for a Site ID.  Populate "
    msg += "the Site ID and the password widgets."
    show_msg(msg, "normal")


def delete_help():
    """help message regarding the delete function"""
    msg = "This will delete the Site ID, Username, and Password from the "
    msg += "Password Manager.\nPopulate the Site ID widget."
    show_msg(msg, "normal")


if __name__ == "__main__":
    app = tk.Tk()
    #
    app.option_add("*Font", "TkFixedFont")
    app.geometry("700x570")
    app.title("Yet Another Password Manager")
    #
    ## Configure menu bar
    #
    menu_bar = tk.Menu(app)
    app.config(menu=menu_bar)
    file_menu = Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="File", menu=file_menu, underline=0)
    file_menu.add_command(label="Clear Fields", command=clear_fields, underline=2)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=write_file_exit, underline=1)
    help_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Help", menu=help_menu, underline=0)
    help_menu.add_command(label="Add", command=add_help, underline=0)
    help_menu.add_command(label="Get", command=get_help, underline=0)
    help_menu.add_command(label="List", command=list_help, underline=0)
    help_menu.add_command(label="Update", command=update_help, underline=0)
    help_menu.add_command(label="Delete", command=delete_help, underline=0)
    app.protocol("WM_DELETE_WINDOW", write_file_exit)

    app.rowconfigure(0, weight=1)
    app.rowconfigure(1, weight=1)
    app.rowconfigure(2, weight=1)
    app.rowconfigure(3, weight=1)
    app.rowconfigure(4, weight=1)
    app.rowconfigure(5, weight=1)
    app.rowconfigure(6, weight=1)
    app.columnconfigure(0, weight=1)
    app.columnconfigure(1, weight=1)
    app.columnconfigure(2, weight=1)
    app.columnconfigure(3, weight=1)

    # site_id_block
    label_site = tk.Label(app, text="SITE ID:")
    label_site.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
    entry_site = tk.Entry(app)
    entry_site.focus()
    entry_site.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

    # Username block
    label_name = tk.Label(app, text="USERNAME:")
    label_name.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
    entry_name = tk.Entry(app)
    entry_name.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

    # Password block
    label_password = tk.Label(app, text="PASSWORD:")
    label_password.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
    entry_password = tk.Entry(app, show="*")
    entry_password.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

    #    # Add button
    button_add = tk.Button(app, text="Add")
    button_add.grid(row=0, column=3, padx=15, pady=8, sticky="we")
    button_add.bind("<Return>", add)
    button_add.bind("<Button-1>", add)

    #    # Get button
    button_get = tk.Button(app, text="Get")
    button_get.grid(row=1, column=3, padx=15, pady=8, sticky="we")
    button_get.bind("<Return>", get)
    button_get.bind("<Button-1>", get)

    #    # List Button
    button_list = tk.Button(app, text="List")
    button_list.grid(row=2, column=3, padx=15, pady=8, sticky="we")
    button_list.bind("<Return>", getlist)
    button_list.bind("<Button-1>", getlist)

    #    # Update password button
    button_update = tk.Button(app, text="Update")
    button_update.grid(row=3, column=3, padx=15, pady=8, sticky="we")
    button_update.bind("<Return>", update)
    button_update.bind("<Button-1>", update)

    #    # Delete button
    button_delete = tk.Button(app, text="Delete", bg="red", font="bold")
    button_delete.grid(row=4, column=3, padx=15, pady=8, sticky="we")
    button_delete.bind("<Return>", delete)
    button_delete.bind("<Button-1>", delete)

    # Text block
    text_font = Font(family="TkFixedFont", size=12)
    T = tk.Text(
        app,
        height=10,
        width=40,
        wrap="word",
        state="disabled",
        bg="yellow",
        font=text_font,
    )
    T.grid(row=6, column=1, padx=10, pady=5)
    #
    ys = tk.Scrollbar(app, orient="vertical", command=T.yview, takefocus=1)
    T["yscrollcommand"] = ys.set
    T.tag_configure("warning", foreground="red")
    T.tag_configure("normal", foreground="black")
    T.grid(column=1, row=6, sticky="nwes")
    ys.grid(column=2, row=6, sticky="ns")
    app.grid_columnconfigure(0, weight=1)
    app.grid_rowconfigure(0, weight=1)
    #
    create_rc_dir()
    cipher = load_encryption_key()
    load_initial_json_file(cipher)
    app.mainloop()
