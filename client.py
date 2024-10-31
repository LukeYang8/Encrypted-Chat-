import socket
import sys
import threading
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

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
        except:
            break

# Function to encrypt message using AES
def encrypt_message_aes(aesKey, message):
    cipher_aes = AES.new(aesKey, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    return cipher_aes.nonce + tag + ciphertext

# Generate RSA key pair
key = RSA.generate(1024)
privateKey = key.exportKey()
publicKey = key.publickey().exportKey()


# Connect to server 
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(('localhost', 8888))

# Exhange public keys
socket.send(publicKey)
print('Waiting for public key ...')
otherPublicKey = socket.recv(4096)
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


# Send messages
while True:

    message = input('Your message: ')
    if message == 'exit':
        break
    message = "Recieved: " + message
    message = encrypt_message_aes(aesKey, message.encode())
    socket.send(message)
    

socket.close()