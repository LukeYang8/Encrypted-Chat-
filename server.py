import socket
import sys
import threading
import signal
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

clients = [
    ["ben", "1234"],
    ["jane", "5678"],
    ["john", "helloworld"]
]
users = 0

# generate RSA keys
key = RSA.generate(1048)
privateKey = key.exportKey()
publicKey = key.publickey().exportKey()
myRsaCipher = PKCS1_OAEP.new(RSA.importKey(privateKey))

def handle_client(client, client2):
    while True:
        message = client.recv(1024)
        
        if not message:
            break
        client2.send(message)
    
    client.close()


def signal_handler(sig, frame):
    print('Closing server ...')
    server.close()
    sys.exit(0)

def main():
    global server
    serverPort = 8888
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', serverPort))
    server.listen(2)
    print('Server is listening on port %s ...' % serverPort)
    
    signal.signal(signal.SIGINT, signal_handler)

    client1, addr1 = server.accept()
    client1.send(publicKey)
    while True:
        message = client1.recv(1024)
        message = myRsaCipher.decrypt(message)
        username, password = message.decode().split()[1:]
        print(username, password)
        if [username, password] in clients:
            client1.send("auth".encode())
            break
        else:
            client1.send("not auth".encode())
    print('Client 1 connected: %s' % str(addr1))
    
    client2, addr2 = server.accept()
    client2.send(publicKey)
    while True:
        message = client2.recv(1024)
        message = myRsaCipher.decrypt(message)
        username, password = message.decode().split()[1:]
        print(username, password)
        if [username, password] in clients:
            client2.send("auth".encode())
            break
        else:
            client2.send("not auth".encode())
    print('Client 2 connected: %s' % str(addr2))

    client1.send("ready".encode())
    client2.send("ready".encode())
    
    thread1 = threading.Thread(target=handle_client, args=(client1, client2))
    thread2 = threading.Thread(target=handle_client, args=(client2, client1))
    
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()

    socket.close()

if __name__ == '__main__':
    main()