# 35459980
# 41093615
# 44214987


from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
import tkinter as tk
import OwnAlgorithm
import rsa  # Import all tkinter
import os

root = Tk()
root.title("General RSA Algorithm")
root.resizable(width=False, height=False)

app_width = 400
app_height = 450

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x = (screen_width / 2) - (app_width / 2)
y = (screen_height / 2) - (app_height / 2)

root.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')  # Creates the size and width of the GUI

root.configure(bg='white')  # Change the background color


# .................USER PASSWORD....................#
def StorePassword(filename):
    userPassword = textbox_password.get("1.0", "end")  # Extract password from user's text box
    file = open(filename + "_Password", "w")  # Writes a file
    password = userPassword
    file.write(password)
    file.close()
    print(password)  # Writes users password in a file


# ..................VERIFY USER PASSWORD.....................#
def VerifyPassword(filename):
    userPassword = textbox_password.get("1.0", "end")
    file = open(filename + "_Password", "r")
    StorePassword = file.read()

    if userPassword == StorePassword:
        print('Passwords match........Proceeding with Decryption..............')
        return TRUE
    else:
        print('Passwords do not match, try again')
        return FALSE


# ..............Encryption Method................#
def Encryption():
    fileDirectory = filedialog.askopenfilename(initialdir="/Users/steph/Desktop", title="Select a File", filetypes=(
        ("Text files", "*.txt*"), ("PowerPoint", "*.pptx*"), ("Word files", ".docx"), ("PNG", "*.png*"),
        ("JPEG", "*.jpg*"),
        ("Zip files", ".zip"),
        ("Rar files", ".rar"), ("all files", "*.*")))
    filename = os.path.basename(fileDirectory)

    # ......Generate RSA Key pair for Encryption + Decryption

    (pubKey, privKey) = rsa.newkeys(1024)  # Generate Public + Private Key using RSA

    file = open(filename + "_PrivKey.pem", "wb")
    file.write(privKey.save_pkcs1())  # Store privateKey in a File with Original Selected file name + PrivKey

    file = open(filename + "_PubKey.pem", "wb")
    file.write(pubKey.save_pkcs1())  # Store publickey in a File with Original Selected file name + PubKey

    file = open(filename + '_PubKey.pem', 'rb')
    pubKey = rsa.PublicKey.load_pkcs1(file.read())  # 1 Open the public key for encryption

    # 2 Open the File to be encrypted
    file = open(fileDirectory, 'rb')  # Store chosen File as a variable
    inputFile = file.read()

    blockS = rsa.common.byte_size(pubKey.n) - 20  # Divides into smaller encrypt-able blocks
    encryptedData = b""  # Converts data type into bytes

    for i in range(0, len(inputFile), blockS):
        encryptedData += rsa.encrypt(inputFile[i: i + blockS], pubKey)  # Encrypt the Files

        # Create new encrypted File
    file = open(filename, 'wb')
    file.write(encryptedData)  # Stores new file with -encrypted to indicate it is a newly encrypted file

    messagebox.showinfo("Info", f"File {filename} has been encrypted")  # Message to display file has been encrypted
    StorePassword(filename)  # Store Password in a file


# ..............Decryption Method................#
def Decryption():
    fileDirectory = filedialog.askopenfilename(initialdir="/Users/steph/Desktop", title="Select a File", filetypes=(
        ("Text files", "*.txt*"), ("PowerPoint", "*.pptx*"), ("PNG", "*.png*"), ("JPEG", "*.jpg*"),
        ("Zip/Rar", "*.zip"),
        ("all files", "*.*")))
    filename = os.path.basename(fileDirectory)

    if VerifyPassword(filename) == TRUE:  # Call the verification method to verify passwords match

        file = open(filename + "_PrivKey.pem", "rb")  # 1 open the private key
        privKey = rsa.PrivateKey.load_pkcs1(file.read())

        file = open(fileDirectory, 'rb')  # 2 Open the file you wish to decrypt
        encryptedFile = file.read()  # Store chosen File as a variable

        blockS = rsa.common.byte_size(privKey.n)  # 3 Determine block-sizes for encryption

        # 4 Decrypt the file content
        DecryptedFile = b""  # Converts data type into bytes
        for i in range(0, len(encryptedFile), blockS):
            DecryptedFile += rsa.decrypt(encryptedFile[i:i + blockS], privKey)  # Decrypt the Files piece by piece

        # Create new decrypted File
        file = open(filename, 'wb')  # Stores new file
        file.write(DecryptedFile)

        messagebox.showinfo("Info", f"File {filename} has been decrypted")  # Message to display file has been decrypted
    else:
        messagebox.showinfo("Info",
                            f"Incorrect password please try again")  # Message to display if passwords did not match


# Close the form
def withdraw():
    root.withdraw()


# ..............Gui Components................#

label1 = Label(root, text="Enter Encryption / Decryption Password", bg="white", font=('Arial', 16), foreground="blue")
label1.pack(pady=5)

textbox_password = tk.Text(root, height=1, width=15, relief="solid", font=('Arial', 12))
textbox_password.pack(pady=5)

label1 = Label(root, text="ENCRYPTION", bg="white", font=('Arial', 20), foreground="blue")
label1.pack(pady=5)

btnEncryptFile = tk.Button(root, text="Encrypt a File", font=('Arial', 25), height=1, width=15, command=Encryption)
btnEncryptFile.pack(pady=5)

label1 = Label(root, text="DECRYPTION", bg="white", font=('Arial', 20), foreground="blue")
label1.pack(pady=5)

btnDecryptFile = tk.Button(root, text="Decrypt a File", font=('Arial', 25), height=1, width=15, command=Decryption)
btnDecryptFile.pack(pady=5)

btnOwnAlgorithm = tk.Button(root, text="Use Own Algorithm", fg="Blue", font=('Arial', 25), height=1, width=15,
                            command=OwnAlgorithm.OwnAlgorithmGUI)
btnOwnAlgorithm.pack(pady=30)

# ..............Gui Components................#


root.mainloop()
