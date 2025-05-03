# crypto_utils.py

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Derive a 256-bit AES key from a password using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 = 32 bytes
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)  # random salt
    iv = os.urandom(16)    # random initialization vector
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    enc_path = file_path + '.enc'
    with open(enc_path, 'wb') as f:
        f.write(salt + iv + encrypted)

    return enc_path

# Decrypt a file
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

    dec_path = file_path.replace('.enc', '.dec')
    with open(dec_path, 'wb') as f:
        f.write(decrypted)

    return dec_path





# ui_main.py

import os, json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QLineEdit, QLabel, QListWidget
)
from PyQt6.QtCore import Qt
from crypto_utils import encrypt_file, decrypt_file

HISTORY_FILE = "file_history.json"

class EncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-256 File Encryptor")
        self.setAcceptDrops(True)
        self.setFixedSize(500, 400)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter encryption password")

        self.status_label = QLabel("Drag and drop files or use the buttons.")

        self.encrypt_btn = QPushButton("Encrypt File")
        self.decrypt_btn = QPushButton("Decrypt File")

        self.history_list = QListWidget()
        self.load_history()

        # Button actions
        self.encrypt_btn.clicked.connect(self.select_and_encrypt)
        self.decrypt_btn.clicked.connect(self.select_and_decrypt)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.password_input)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("File History:"))
        layout.addWidget(self.history_list)
        self.setLayout(layout)

    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                files = json.load(f)
                self.history_list.addItems(files)

    def update_history(self, path):
        items = [self.history_list.item(i).text() for i in range(self.history_list.count())]
        if path not in items:
            items.insert(0, path)
        with open(HISTORY_FILE, 'w') as f:
            json.dump(items[:10], f)
        self.history_list.clear()
        self.history_list.addItems(items[:10])

    def select_and_encrypt(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if file:
            self.encrypt(file)

    def select_and_decrypt(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select file to decrypt")
        if file:
            self.decrypt(file)

    def encrypt(self, path):
        password = self.password_input.text()
        if not password:
            self.status_label.setText("Please enter a password.")
            return
        try:
            out_file = encrypt_file(path, password)
            self.status_label.setText(f"Encrypted to: {out_file}")
            self.update_history(out_file)
        except Exception as e:
            self.status_label.setText(f"Encryption error: {e}")

    def decrypt(self, path):
        password = self.password_input.text()
        if not password:
            self.status_label.setText("Please enter a password.")
            return
        try:
            out_file = decrypt_file(path, password)
            self.status_label.setText(f"Decrypted to: {out_file}")
            self.update_history(out_file)
        except Exception as e:
            self.status_label.setText(f"Decryption error: {e}")

    # Drag and drop support
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        password = self.password_input.text()
        if not password:
            self.status_label.setText("Enter a password before dragging files.")
            return
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path.endswith('.enc'):
                self.decrypt(file_path)
            else:
                self.encrypt(file_path)




# main.py

import sys
from PyQt6.QtWidgets import QApplication
from ui_main import EncryptorApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())
