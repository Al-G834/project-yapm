import tkinter as tk
#from tkinter import messagebox
import tkinter.font as font
from tkinter import Menu
import json
from cryptography.fernet import Fernet

passwords = {}


def open_file():
    global passwords
    with open("password.json", "r") as passwords_fh:
        passwords = json.load(passwords_fh)

def close_file():
    global passwords
    with open("password.json", "w") as f:
        json.dump(passwords, f)

def close_file_exit():
    global passwords
    with open("password.json", "w") as f:
        json.dump(passwords, f)
    app.destroy()

def add():
    global passwords

    #open_file()
    # accepting input from the user
    site_id = entry_site.get()
    username = entry_name.get()
    # accepting password input from the user
    password = entry_password.get()
    if not passwords:
        msg = "Error: Password file not open"
    else:
        key_list = list(passwords.keys())
        if site_id in key_list:
            msg = "Error", "The site_id already exists in passwords"
        elif site_id and username and password:
            passwords = {**passwords, site_id: {"username": username, "password": password}}
            msg = "Success, Password added!!"
        else:
            msg = "Error: Please enter all the fields"

    show_msg(msg)

def update():
    global passwords
    # accepting input from the user

    #open_file()
    site = entry_site.get()
    username = entry_name.get()
    pwd = entry_password.get()

    try:
        passwords[f"{site}"].update({"password": f"{pwd}"})
        msg = f"Site ID: {site} updated!!"
    except KeyError:
        msg ="Please provide Site ID"

    #close_file()
    show_msg(msg)

def get():
    global passwords
    # accepting input from the user
    site = entry_site.get()

    #open_file()

    if site in passwords.keys():
        for site_id, info in passwords.items():
            if site == site_id:
                next
            else:
                continue
            msg = f"\n\nSite ID: {site_id}"
            for key in info:
                msg += f"\n{key}: {info[key]}"
    else:
        msg = "Site ID not found!!"

    show_msg(msg)

def getlist():
    global passwords

    #open_file()
    if passwords:
        msg = "List of passwords:\n"
        for site_id, info in passwords.items():
            msg += f"\n\nSite ID: {site_id}"
            for key in info:
                msg += f"\n{key}: {info[key]}"
    else:
        msg = "Empty password file!!"

    #close_file()
    show_msg(msg)

def delete():
    global passwords
    # accepting input from the user
    site_id = entry_site.get()
    # creating a temporary list to store the data
    temp_passwords = {}
    if site_id:
        # reading data from the file and excluding the specified username
        #try:
        #    with open("password.json", "r") as passwords_fh:
        #        temp_passwords = json.load(passwords_fh)

        passwords.pop(site_id, None)
            # writing the modified data back to the file
        #    with open("password.json", "w") as f:
        #        json.dump(passwords, f)
        msg = f"Success SiteID: {site_id} deleted"
        #except Exception as e:
        #    msg = f"JSON error in Update, f{e}"
    else:
        msg = "Please provide Site ID"
    
    close_file()
    show_msg(msg)

def clear_fields():
    entry_site.delete(0, "end")
    entry_name.delete(0, "end")
    entry_password.delete(0, "end")
    T["state"] = "normal"
    T.delete("1.0", tk.END)
    T["state"] = "disabled"

def show_msg(msg):
    # Clear the widget
    T["state"] = "normal"
    T.delete("1.0", tk.END)
    # Showing the msgage
    T.insert("end", msg)
    T["state"] = "disabled"

if __name__ == "__main__":
    app = tk.Tk()
    #
    app.option_add("*Font", "Arial")
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
    file_menu.add_command(label="Open Password File", command=open_file, underline=0)
    #    file_menu.add_command(label="Close Password File", command=close_file, underline=0)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=close_file_exit, underline=1)
    app.protocol("WM_DELETE_WINDOW", close_file_exit)
    #

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
    button_add = tk.Button(app, text="Add", command=add)
    button_add.grid(row=0, column=3, padx=15, pady=8, sticky="we")

    #    # Get button
    button_get = tk.Button(app, text="Get", command=get)
    button_get.grid(row=1, column=3, padx=15, pady=8, sticky="we")

    #    # List Button
    button_list = tk.Button(app, text="List", command=getlist)
    button_list.grid(row=2, column=3, padx=15, pady=8, sticky="we")

    #    # Update password button
    button_update = tk.Button(app, text="Update", command=update)
    button_update.grid(row=3, column=3, padx=15, pady=8, sticky="we")

    #    # Delete button
    button_delete = tk.Button(app, text="Delete", command=delete, bg="red", font="bold")
    button_delete.grid(row=4, column=3, padx=15, pady=8, sticky="we")

    # Text block
    T = tk.Text(app, height=10, width=40, wrap="word", state="disabled", bg="yellow")
    T.grid(row=6, column=1, padx=10, pady=5)
    #
    ys = tk.Scrollbar(app, orient="vertical", command=T.yview)
    xs = tk.Scrollbar(app, orient="horizontal", command=T.xview)
    T["yscrollcommand"] = ys.set
    T["xscrollcommand"] = xs.set
    #    T.insert('end', "Lorem ipsum...\n...\n...")
    T.grid(column=1, row=6, sticky="nwes")
    xs.grid(column=1, row=7, sticky="we")
    ys.grid(column=2, row=6, sticky="ns")
    app.grid_columnconfigure(0, weight=1)
    app.grid_rowconfigure(0, weight=1)
    #
    app.mainloop()
