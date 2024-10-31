import socket
import sys
import threading
import signal

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
    print('Client 1 connected: %s' % str(addr1))
    
    client2, addr2 = server.accept()
    print('Client 2 connected: %s' % str(addr2))
    
    thread1 = threading.Thread(target=handle_client, args=(client1, client2))
    thread2 = threading.Thread(target=handle_client, args=(client2, client1))
    
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()
    
    socket.close()

if __name__ == '__main__':
    main()