from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class Encryptor:

    def __init__(self, file_name,key):
        self.fernet = Fernet(key=key, backend=default_backend())
        self.file_name = file_name

    def encrypt(self):
        encrypted = self.fernet.encrypt(self.file_data())
        self.write_file(encrypted)

    def decrypt(self):
        decrypted = self.fernet.decrypt(self.file_data())
        self.write_file(decrypted)

    def file_data(self):
        with open(self.file_name, "rb") as f:
            data = f.read()
        return data

    def write_file(self, encrypted):
        with open(self.file_name, "wb") as f:
            f.write(encrypted)
