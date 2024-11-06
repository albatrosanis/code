import socket
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(message)
            else:
                break
        except:
            print("Error receiving message.")
            break

def send_message():
    while True:
        message = input()
        client_socket.send(message.encode('utf-8'))
        if message.lower() == 'exit':
            print("Disconnecting...")
            client_socket.close()
            break

# Authenticate with the server
def authenticate():
    username = input("")
    client_socket.send(username.encode('utf-8'))
    password = input("")
    client_socket.send(password.encode('utf-8'))

# Start receiving thread
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

authenticate()

# Start sending thread
send_thread = threading.Thread(target=send_message)
send_thread.start()
