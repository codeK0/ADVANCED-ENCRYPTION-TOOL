# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*:  Kanchan Vilas Jadhav

*INTERN ID*: CT04DA375

*DOMAIN*: Cyber Security & Ethical Hacking

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

# DESCRIPTION OF TASK: 

# Editor used: VS Studio

# 📁File 1: crypto_utils.py
-Purpose: Handles AES-256 encryption and decryption logic.
 derive_key(password, salt)

-What it does:

Uses your password + a random salt to create a secure 256-bit key.

Uses PBKDF2 (a secure key derivation algorithm) with SHA-256.

def derive_key(password, salt):
    kdf = PBKDF2HMAC(...)
    return kdf.derive(password.encode())

-Why:

We never use the password directly as an encryption key.

This makes brute-forcing much harder.

✅ encrypt_file(file_path, password)
-What it does:

~Reads your file into bytes.

~Generates a salt and IV (Initialization Vector).

~Derives an AES key using your password and salt.

~Encrypts the file using AES in CFB (Cipher Feedback) mode.

~Writes out a new file: [original name].enc, with the salt + IV + ciphertext.


cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
encrypted = encryptor.update(data) + encryptor.finalize()
Output: A .enc file that only your password can decrypt.

✅ decrypt_file(file_path, password)
-What it does:

~Reads an encrypted file.

~Extracts the salt and IV.

~Re-derives the key using your password + extracted salt.

~Decrypts the data with AES.

~Writes out a new file [original name].dec.

decrypted = decryptor.update(encrypted_data) + decryptor.finalize()


# 📁 File 2: ui_main.py
-Purpose: Defines the PyQt6 GUI logic.

✅ EncryptorApp(QWidget)
This class is the main app window.

- UI Components:
QLineEdit: for password input.

QPushButton: for encrypt/decrypt.

QListWidget: to show file history.

QLabel: to display messages.

setAcceptDrops(True): allows drag-and-drop support.

✅ load_history() and update_history(path)
These manage the file history list (stored in file_history.json):

Load history on startup.

Save a list of recent encrypted/decrypted files.

Show them in the bottom list.

✅ select_and_encrypt() / select_and_decrypt()
Show a file dialog to let you choose a file.

When a file is selected, it encrypts/decrypts using your password.

Results are shown in a label.

History is updated.

✅ encrypt(path) and decrypt(path)
These functions:

Read the password from the field.

Call encrypt_file or decrypt_file.

Show success or error messages.

✅ dragEnterEvent() and dropEvent()
These handle drag and drop:

Accepts files dragged into the window.

Encrypts or decrypts automatically based on file extension.

If .enc → decrypt

Else → encrypt

# 📁 File 3: main.py
-Purpose: Launch the GUI app.

from ui_main import EncryptorApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())
-This is the entry point. It:

Creates a Qt application.

Loads the GUI window.

Starts the event loop (to wait for clicks, drags, etc.).

📦 Summary
-Feature	Where It's Handled

AES-256 encryption	crypto_utils.encrypt_file()
AES-256 decryption	crypto_utils.decrypt_file()
Password input	QLineEdit in ui_main.py
Drag-and-drop	dragEnterEvent() + dropEvent()
File picker	QFileDialog.getOpenFileName()
File history	JSON file + QListWidget
GUI Window	PyQt6 via EncryptorApp(QWidget)


# Output: 
<img width="383" alt="Image" src="https://github.com/user-attachments/assets/a0d198e0-3c65-411a-bce6-013c7b8b06b2" />
