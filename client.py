import socket
import sys
import threading
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from tkinter import scrolledtext
from tkinter import *

root = Tk()
root.title("Chat")
root.geometry("500x600")

appHeader = Label(root, text="Encrypted Chat", bg = "blue", fg="white", font=("Georgia",24), height=1)
appHeader.pack(fill=BOTH, expand=True)

displayText = scrolledtext.ScrolledText(root, state=DISABLED, wrap=WORD)
displayText.pack(fill=BOTH, expand=True)  

inputText = scrolledtext.ScrolledText(root, state=NORMAL, wrap=WORD, height=5)
inputText.pack(fill=BOTH, expand=True)


#
def displayMessage(message):
    displayText.config(state=NORMAL)
    displayText.insert(END, message + '\n')
    displayText.config(state=DISABLED)
    displayText.see(END)

# Function to decode message
def decodeMessage(socket, aesKey):
    while True:
        try:
            message = socket.recv(1024)
            if not message:
                break
            nonce = message[:16]
            tag = message[16:32]
            ciphertext = message[32:]
            cipherAes = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
            # ensure the integrity of the message
            decyptedMessage = cipherAes.decrypt_and_verify(ciphertext, tag)
            print('\n' + decyptedMessage.decode() + '\nYour message: ', end='')
            displayMessage(decyptedMessage.decode())
        except:
            break

# Function to encrypt message using AES
def encrypt_message_aes(aesKey, message):
    cipher_aes = AES.new(aesKey, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    return cipher_aes.nonce + tag + ciphertext

def send_message(username, socket, aesKey):

    message = inputText.get("1.0", END).strip()
    displayMessage("Me: " + message)
    if message == 'exit':
        socket.close()
        sys.exit(0)
    message = f"{username.capitalize()}: {message}"
    message = encrypt_message_aes(aesKey, message.encode())
    socket.send(message)
    inputText.delete("1.0", END)


def get_message():
    message = inputText.get("1.0", END).strip()
    if message == 'exit':
        socket.close()
        sys.exit(0)
    return message

# Generate RSA key pair
key = RSA.generate(1024)
privateKey = key.exportKey()
publicKey = key.publickey().exportKey()

# Connect to server and get server key
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(('localhost', 8888))
serverKey = socket.recv(1024)
serverKey = RSA.importKey(serverKey)
serverRsaCipher = PKCS1_OAEP.new(serverKey)
displayMessage("Connected to Server ...")
displayMessage("Enter your login details")
authenticated = False

# def login(socket, serverRsaCipher):
#     def verify(username, password, socket, serverRsaCipher):
#         message = f"auth {username} {password}"
#         socket.send(serverRsaCipher.encrypt(message.encode()))
#         res = socket.recv(1024)
#         if res.decode() == "auth":
#             print("Authenticated2")
#             login.destroy()
#         else:
#             login.destroy()
#             login()



#     login = Tk()
#     login.title("Login")
#     login.geometry("200x200")

#     Label(login, text="Username", bg = "lightblue", fg="white", font=("Georgia",15), height=1).pack(pady=3)
#     username = Entry(login, show="*" ,width=10)
#     username.pack(pady=5)

#     Label(login, text="Password", bg = "lightblue", fg="white", font=("Georgia",15), height=1).pack(pady=3)
#     password = Entry(login, show="*", width=10)
#     password.pack(pady=5)

#     Button(login, text="Login", bg="blue", fg="white", font=("Georgia",15), command=lambda: verify(username, password, socket, serverRsaCipher)).pack(pady=1)

#     login.mainloop()


# login()

username = ""
while not authenticated:
    # displayMessage("Username: ")
    # username = inputText.bind("<Return>", lambda x: get_message())
    # displayMessage("Password: ")
    # password = inputText.bind("<Return>", lambda x: get_message())
    
    username = input("Username: ")
    username = username.replace(" ", "")
    password = input("Password: ")
    password = password.replace(" ", "")
    message = f"auth {username} {password}"
    socket.send(serverRsaCipher.encrypt(message.encode()))
    res = socket.recv(1024)
    if res.decode() == "auth":
        authenticated = True
    else:
        print("Wrong login details, please try again")

print("Authenticated")
displayMessage("Authenticated")
displayMessage("Waiting for other user ...")
socket.recv(1024)


# Exhange public keys
socket.send(publicKey)
otherPublicKey = socket.recv(1024)
otherPublicKey = RSA.importKey(otherPublicKey)
otherRsaCipher = PKCS1_OAEP.new(otherPublicKey)

myRsaCipher = PKCS1_OAEP.new(RSA.importKey(privateKey))

# Use RSA to exchange AES key
aesKey = Crypto.Random.get_random_bytes(16)
aesKeyEncrypted = otherRsaCipher.encrypt(aesKey)
socket.send(aesKeyEncrypted)

otherAesKeyEncrypted = socket.recv(1024)
otherAesKey = myRsaCipher.decrypt(otherAesKeyEncrypted)


# Thread to allow multithreading in sending messages
thread = threading.Thread(target=decodeMessage, args=(socket, otherAesKey))
thread.start()

# print("Connected to server2")
# thread2 = threading.Thread(target=send_message, args=(username, socket, aesKey))
# thread2.start()

# Send messages
# while True:
#     send_message()
displayMessage("... You may now start chatting ...")
inputText.bind("<Return>", lambda x: send_message(username, socket, aesKey))
root.mainloop()

# root = Tk()
# root.title("Chat")
# root.geometry("500x700")  
# displayText = scrolledtext.ScrolledText(root, state=DISABLED, wrap=WORD)
# displayText.pack(fill=BOTH, expand=True)  
# root.mainloop()

