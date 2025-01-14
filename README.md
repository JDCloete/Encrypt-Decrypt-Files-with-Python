# File Encryption and Decryption Tool

This project provides a GUI application for file encryption and decryption using two methods: RSA encryption and a custom XOR-based algorithm with SHA-256 password hashing. The application is built using Python and Tkinter, offering a user-friendly interface for managing file security.

---

## Features
- **RSA Encryption**: Encrypt files using public/private key pairs.
- **Custom Algorithm**: Use XOR-based encryption secured by SHA-256 hashed passwords.
- **Password Protection**: Store and verify passwords for decryption.
- **User-Friendly GUI**: Perform all operations easily with a graphical interface.

---

## Usage

### Running the Application
1. **From Source**:
   - Ensure Python is installed on your system.
   - Install the required libraries using `pip install rsa`.
   - Run the program:
     ```bash
     python GeneralAlgorithm.py
     ```
2. **Using the Executable**:
   - Download the `.exe` file.
   - Run the executable inside a folder to avoid clutter. It generates the following files:
     - Public and private RSA key files.
     - Encrypted files.
     - Encrypted passphrase files.

---

## Prerequisites
- Python 3.6 or later
- Required Python libraries:
  - `rsa`
  - `tkinter`

---

## How It Works
1. Enter a password for encryption or decryption.
2. Select a file to encrypt or decrypt through the GUI.
3. The application generates necessary key files and secures your data.

---

## Notice
- When using the `.exe`, ensure it is run inside a dedicated folder. This is because it generates key files, encrypted files, and password files in the same directory.

---

## Acknowledgments
Special thanks to the developers and contributors of Python, Tkinter, and the `rsa` library for making this project possible.
