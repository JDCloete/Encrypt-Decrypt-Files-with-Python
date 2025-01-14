# 35459980
# 41093615
# 44214987

from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
import tkinter as tk
import hashlib
import os


# Create a Window widget

def OwnAlgorithmGUI():
    root = Tk()
    root.title("Own Algorithm")
    root.resizable(width=False, height=False)

    app_width = 400
    app_height = 450

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    x = (screen_width / 2) - (app_width / 2)
    y = (screen_height / 2) - (app_height / 2)

    root.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')  # Creates the size and width of the GUI

    root.configure(bg='white')  # Change the background color

    ### Generate a hashed Password inside a method ###
    def generateHash(PassW):
        h = hashlib.sha256()
        password = f'{PassW}'  # Assigns password to the user's input password
        h.update(password.encode())  # Encode the password using hashlib
        password_hash = h.hexdigest()  # Create new hashed variable
        print(password_hash)
        return password_hash

    ### Encryption Method ###
    def Encryption(inputPassword, password_hash):
        fileDirectory = filedialog.askopenfilename(initialdir="/Users/steph/Desktop", title="Select a File", filetypes=(
            ("Text files", "*.txt*"), ("PowerPoint", "*.pptx*"), ("PNG", "*.png*"), ("JPEG", "*.jpg*"),
            ("Zip/Rar", "*.zip"), ("all files", "*.*")))
        filename = os.path.basename(fileDirectory)

        file = open(filename, "rb")  # Read the file which is going to be encrypted
        data = file.read()
        file.close()

        ##################################  ALGORITHM                           # Encrypt the file using the algorithm
        data = bytearray(data)
        for index, value in enumerate(data):
            data[index] = value ^ (len(password_hash) * 2)
        ##################################  ALGORITHM

        os.remove(filename)  # Delete original file after encryption
        file = open(filename, "wb")  # Save a new file with the same name as the original except it is encrypted
        file.write(data)  # Store encrypted data
        file.close()
        messagebox.showinfo("Info",
                            f"File {filename} has been encrypted")  # Messagebox to show that the data has been encrypted
        StorePassword(password_hash, filename)  # Stores input password as file

    ### Decryption Method ###
    def Decrypt(password_hash):
        fileDirectory = filedialog.askopenfilename(initialdir="/Users/steph/Desktop", title="Select a File", filetypes=(
            ("Text files", "*.txt*"), ("PowerPoint", "*.pptx*"), ("PNG", "*.png*"), ("JPEG", "*.jpg*"),
            ("Zip/Rar", "*.zip"), ("all files", "*.*")))
        filename = os.path.basename(fileDirectory)

        if VerifyPassword(filename, password_hash) == True:  # Tests whether passwords are equal

            file = open(filename, "rb")  # Read the encrypted File
            data = file.read()
            file.close()

            ##################################  ALGORITHM                       # Decrypting Algorithm
            data = bytearray(data)
            for index, value in enumerate(data):
                data[index] = value ^ (len(password_hash) * 2)
            ##################################  ALGORITHM                       # Decrypting Algorithm

            os.remove(filename)  # Delete the encrypted file after decryption
            file = open(filename,
                        "wb")  # Stores decrypted file with the same name as original encrypted file except it is now decrypted
            file.write(data)
            file.close()
            messagebox.showinfo("Info", f"File {filename} has been decrypted")
        else:
            messagebox.showinfo("Info", "Passwords do not match, try again.")

    # Button method for Encrypt
    def EncryptButton():  # Method to encrypt and use in button command
        inputPassword = txtEPassword.get("1.0", "end")  # Extract value from text box
        password_hash = generateHash(inputPassword)  # Generate Hash password
        Encryption(inputPassword, password_hash)  # Run the encryption method

    # Button method for Decrypt
    def DecryptButton():
        DecryptPassword = txtDPassword.get("1.0", "end")
        password_hash = generateHash(DecryptPassword)  # Hash the entered password to run it with
        Decrypt(password_hash)

        # Method to verify decrypted password is equal to Encrypted password

    def VerifyPassword(filename, password_hash):
        PasswordFile = open(filename + "-Password.txt", "r")
        PasswordFile = PasswordFile.read()
        print("Password: " + PasswordFile)

        if password_hash == PasswordFile:
            print("passwords match")
            return True  # Verification Successful
        else:
            print("passwords do not match")
            return False  # Verification Failed

    # Method to store password in a file
    def StorePassword(password_hash, filename):
        File = open(filename + "-Password.txt", "w")  # Stores password in a textfile as string
        outData = password_hash  # Variable to write into a file
        File.write(outData)
        File.close()

    def Exit():
        root.withdraw()

    ########.......GUI CODE.......#########

    label1 = Label(root, text="Enter Encryption Password", bg="white", fg="Black", font=('Arial', 15),
                   foreground="Black")
    label1.pack(pady=8)

    txtEPassword = tk.Text(root, height=1, width=20, relief="solid",
                           font=('Arial', 12))  # Create a textbox control for Encryption password
    txtEPassword.pack(pady=8)

    btnEncryptFile = tk.Button(root, text="Encrypt a File", fg="Black", font=('Arial', 25), height=1, width=15,
                               command=EncryptButton)
    btnEncryptFile.pack(pady=8)

    label1 = Label(root, text="Enter Decryption Password", bg="white", fg="Black", font=('Arial', 15),
                   foreground="Black")
    label1.pack(pady=8)

    txtDPassword = tk.Text(root, height=1, width=20, relief="solid", font=('Arial', 12))  # Create a textbox control
    txtDPassword.pack(pady=8)

    btnDecryptFile = tk.Button(root, text="Decrypt a File", fg="Black", font=('Arial', 25), height=1, width=15,
                               command=DecryptButton)
    btnDecryptFile.pack(pady=8)

    btnExit = tk.Button(root, text="Exit", fg="Black", font=('Arial', 20), height=1, width=10, command=Exit)
    btnExit.pack(pady=20)

    ########.......GUI CODE.......#########

    root.mainloop()  # END OF APPLICATION
