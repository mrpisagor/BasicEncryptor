import os
import tkinter as tk
from tkinter.font import Font
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
from tkinter.messagebox import askyesno, showwarning
from cryptography.fernet import Fernet
from encryption import Encryptor
from bcrypt import checkpw
import sqlite3


def dict_factory(cur, row):
    d = {}
    for idx, col in enumerate(cur.description):
        d[col[0]] = row[idx]
    return d

con = sqlite3.connect("encryptorDB.db")
con.row_factory = dict_factory
cursor = con.cursor()


class App:

    def __init__(self, master):
        # Root
        self.selection = None
        self.file_info = None
        self.master = master
        self.master.geometry("800x500+320+80")
        self.master.title("File encryptor")
        self.master.iconbitmap(default="images/padlock.ico")
        # Fonts
        arial13 = Font(family="Times", size=13)
        # Buttons frame
        self.button_frame = tk.Frame(self.master)
        # Add button
        self.add_button_image = tk.PhotoImage(file="images/buttonadd.png")
        self.add_button = tk.Button(self.button_frame, image=self.add_button_image, borderwidth=0,
                                    command=self.get_file)
        self.add_button.grid(row=0, column=0, padx=(0, 10))
        # Discard button
        self.discard_button_image = tk.PhotoImage(file="images/buttondelete.png")
        self.discard_button = tk.Button(self.button_frame, image=self.discard_button_image, borderwidth=0,
                                        command=self.remove_file)
        self.discard_button.grid(row=0, column=1, padx=(10, 0))

        self.button_frame.pack(pady=(10, 20))
        # Scroll bar
        self.scroll_bar = tk.Scrollbar(self.master)
        self.scroll_bar.pack(side=tk.RIGHT, fill=tk.Y)
        # Listbox
        self.listBox = tk.Listbox(self.master, font=arial13)

        data = cursor.execute("SELECT * FROM files").fetchall()

        for i in data:

            status_symbol = chr(128274) if i["encrypted"] else chr(128275)
            self.listBox.insert(tk.END, i["path"] + " " + status_symbol)
        self.listBox.config(borderwidth=0, activestyle="none")
        self.listBox.bind("<<ListboxSelect>>", self.file_action)
        self.listBox.pack(fill=tk.BOTH, pady=(0, 30))
        self.listBox.configure(yscrollcommand=self.scroll_bar.set)
        self.scroll_bar.configure(command=self.listBox.yview)
        # File info frame
        self.info = tk.Frame(self.master)
        # Decrypt button
        self.decrypt_button_image = tk.PhotoImage(file="images/decryptbutton.png")
        self.decrypt_button = tk.Button(self.info, image=self.decrypt_button_image, borderwidth=0,
                                        command=self.decrypt_file)
        self.decrypt_button.grid(column=0, row=0, padx=(0, 5))
        # Encrypt button
        self.encrypt_button_image = tk.PhotoImage(file="images/encryptbutton.png")
        self.encrypt_button = tk.Button(self.info, image=self.encrypt_button_image, borderwidth=0,
                                        command=self.encrypt_file)
        self.encrypt_button.grid(column=1, row=0, padx=(5, 0))
        # Status label
        self.image_lock = tk.PhotoImage(file="images/lock.png")
        self.image_unlock = tk.PhotoImage(file="images/unlock.png")
        self.status_label = tk.Label(self.info, font="Arial 25")
        self.status_label.grid(column=0, row=1, pady=(30, 0))
        self.image_frame = tk.Label(self.info)
        self.image_frame.grid(column=1, row=1, pady=(30, 0))

    def decrypt_file(self):
        password = simpledialog.askstring(title="Authenticate", prompt="Please enter the password".center(100, " "),
                                          show="*", parent=root)
        if password is not None:

            if checkpw(password.encode(), cursor.execute("SELECT * FROM passwords").fetchone()["password"].encode()):
                encryptor = Encryptor(self.file_info["path"], self.file_info["key"])
                encryptor.decrypt()

                cursor.execute("UPDATE files SET encrypted=FALSE WHERE id=?", (self.file_info["id"],))
                con.commit()

                self.file_info["encrypted"] = False
                self.encrypt_button.configure(state="normal")
                self.decrypt_button.configure(state="disabled")
                selection = self.selection
                self.listBox.delete(selection)
                self.listBox.insert(selection, self.file_info["path"] + " " + chr(128275))
                self.status_label.configure(
                    text="Status: Not Encrypted", fg="green")
                self.image_frame.configure(image=self.image_unlock)
                self.listBox.selection_set(selection)

    def encrypt_file(self):
        real_password_record = cursor.execute("SELECT * FROM passwords").fetchone()
        if real_password_record is None:
            showwarning("Password required", "Please save a password to database")
            return
        password = simpledialog.askstring(title="Authenticate", prompt="Please enter the password".center(100, " "),
                                          show="*", parent=root)
        if password is not None:

            if checkpw(password.encode(), real_password_record["password"].encode()):
                encryptor = Encryptor(self.file_info["path"], self.file_info["key"])
                encryptor.encrypt()

                cursor.execute("UPDATE files SET encrypted=TRUE WHERE id=?", (self.file_info["id"],))
                con.commit()

                self.file_info["encrypted"] = True
                self.encrypt_button.configure(state="disabled")
                self.decrypt_button.configure(state="normal")
                selection = self.selection
                self.listBox.delete(selection)
                self.listBox.insert(selection, self.file_info["path"] + " " + chr(128274))
                self.status_label.configure(
                        text="Status: Encrypted", fg="red")
                self.image_frame.configure(image=self.image_lock)
                self.listBox.selection_set(selection)

    def file_action(self, event):
        if event.widget.size() != 0 and len(event.widget.curselection()) != 0:
            # Selected file
            self.selection = event.widget.curselection()
            selected_file = event.widget.get(self.selection).rsplit(maxsplit=1)[0]
            self.file_info = cursor.execute("SELECT * FROM files WHERE path=?", (selected_file,)).fetchone()
            self.status_label.configure(
                text="Status: Encrypted" if self.file_info["encrypted"] else "Status: Not Encrypted",
                fg="red" if self.file_info["encrypted"] else "green")
            self.image_frame.configure(image=self.image_lock if self.file_info["encrypted"] else self.image_unlock)
            self.info.pack(anchor=tk.CENTER)
            # Enabled
            if self.file_info["encrypted"]:
                self.encrypt_button.config(state="disabled")
                self.decrypt_button.config(state="normal")
            else:
                self.encrypt_button.config(state="normal")
                self.decrypt_button.config(state="disabled")

    def remove_file(self):
        if self.listBox.size() != 0 and len(self.listBox.curselection()) != 0:
            if self.file_info["encrypted"]:
                status = askyesno("Are you sure", "If you delete the file data it will be gone permanently")
            else:
                status = True
            if status:

                cursor.execute("DELETE FROM files WHERE path=?", (self.file_info["path"],))
                con.commit()
                selection = self.listBox.curselection()
                self.listBox.delete(selection)
                self.info.pack_forget()

    def get_file(self):
        opened_file = askopenfilename(
            title="Open a file",
            initialdir=os.getenv("HOME"),
            filetypes=[("All files", "*")]
        )
        if len(opened_file) != 0:

            data = cursor.execute("SELECT * FROM files WHERE path=?", (opened_file,)).fetchone()
            if data is None:
                file_name = os.path.basename(opened_file)
                key = Fernet.generate_key()

                cursor.execute("INSERT INTO files(name,path,key,encrypted) VALUES (?,?,?,?)",
                               (file_name, opened_file, key, False))
                cursor.execute("INSERT INTO backupfiles(name,path,key) VALUES (?,?,?)", (file_name, opened_file, key))
                con.commit()

                self.listBox.insert(tk.END, opened_file + " " + chr(128275))
                if len(self.listBox.curselection()) != 0:
                    self.listBox.selection_clear(self.listBox.curselection())
                self.info.pack_forget()


if __name__ == "__main__":

    root = tk.Tk()
    app = App(root)
    root.mainloop()
    con.close()
