import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"Server started on {HOST}:{PORT}")

clients = []
usernames = {}
authenticated_users = {'Anis': 'Anis01', 'Chakib': 'Chakib01', 'a': 'a', 'b': 'b'}
user_status = {}
channels = {}  # Dictionary for channels
user_channel = {}  # Dictionary to store the current channel of each client
private_channel_passwords = {}  # Dictionary to store passwords for private channels

def handle_client(client_socket, client_address):
    print(f"New connection from {client_address}")
    clients.append(client_socket)
    
    if not authenticate_user(client_socket):
        client_socket.send("Authentication failed. Disconnecting.".encode('utf-8'))
        client_socket.close()
        return
    
    display_active_users(client_socket)

    username = usernames[client_socket]
    user_status[username] = "online"
    broadcast(f"{username} has joined the chat!", client_socket)

    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            if message.startswith('/'):
                handle_command(client_socket, message)
            else:
                # Check if the user is in a channel
                if client_socket in user_channel and user_channel[client_socket]:
                    channel_name = user_channel[client_socket]
                    send_channel_message(client_socket, channel_name, f"{username}: {message}")
                else:
                    broadcast(f"{username}: {message}", client_socket)
    except:
        pass
    finally:
        clients.remove(client_socket)
        user_status[username] = "offline"
        broadcast(f"{username} has left the chat.", client_socket)
        client_socket.close()
        del usernames[client_socket]
        if client_socket in user_channel:
            del user_channel[client_socket]
        print(f"BYE BYE {client_address}")

def authenticate_user(client_socket):
    client_socket.send("Username: ".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8')
    client_socket.send("Password: ".encode('utf-8'))
    password = client_socket.recv(1024).decode('utf-8')
    
    if authenticated_users.get(username) == password:
        usernames[client_socket] = username
        client_socket.send("Welcome to Anisalba Server.\n".encode('utf-8'))
        return True
    else:
        client_socket.send("NOP Wrong username or password.\n".encode('utf-8'))
        return False

def display_active_users(client_socket):
    active_users = "Online users:\n"
    for user, status in user_status.items():
        active_users += f"{user} ({status})\n"
    client_socket.send(active_users.encode('utf-8'))

def broadcast(message, sender_client=None):
    for client in clients:
        if client != sender_client:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)

def handle_command(client, command):
    username = usernames.get(client, "Unknown")
    if command.startswith("/help"):
        help_message = "/nick <new_nickname> - Change nickname\n" \
                       "/list - Show all active users\n" \
                       "/broadcast <message> - Send to all\n" \
                       "/private <username> <message> - Send private message\n" \
                       "/create <channel> [password] - Create a new channel\n" \
                       "/join <channel> [password] - Join a channel\n" \
                       "/leave <channel> - Leave a channel\n" \
                       "/channels - List all available channels\n"
        client.send(help_message.encode('utf-8'))
    
    elif command.startswith("/nick "):
        new_nickname = command.split(' ', 1)[1]
        change_nickname(client, new_nickname)
    
    elif command.startswith("/channels"):
        list_channels(client)
    
    elif command.startswith("/list"):
        display_active_users(client)
    
    elif command.startswith("/broadcast "):
        message = command.split(' ', 1)[1]
        broadcast(f"[Broadcast] {username}: {message}", sender_client=client)
    
    elif command.startswith("/private "):
        parts = command.split(' ', 2)
        target_username, private_message = parts[1], parts[2]
        send_private_message(client, target_username, private_message)
    
    elif command.startswith("/create "):
        parts = command.split(' ', 2)
        channel_name = parts[1]
        password = parts[2] if len(parts) > 2 else None
        create_channel(client, channel_name, password)
    
    elif command.startswith("/join "):
        parts = command.split(' ', 2)
        channel_name = parts[1]
        password = parts[2] if len(parts) > 2 else None
        join_channel(client, channel_name, password)
    
    elif command.startswith("/leave "):
        channel_name = command.split(' ')[1]
        leave_channel(client, channel_name)
    
    else:
        client.send("Unknown command. Type /help for a list of commands.".encode('utf-8'))

def change_nickname(client, new_nickname):
    old_username = usernames[client]
    usernames[client] = new_nickname
    user_status[new_nickname] = user_status.pop(old_username)
    broadcast(f"{old_username} changed nickname to {new_nickname}.", client)

def send_private_message(sender_client, target_username, message):
    for client, username in usernames.items():
        if username == target_username:
            client.send(f"[Private] {usernames[sender_client]}: {message}".encode('utf-8'))
            sender_client.send(f"[Private to {target_username}] {message}".encode('utf-8'))
            return
    sender_client.send(f"User {target_username} not found.".encode('utf-8'))

def send_channel_message(client, channel_name, message):
    if channel_name in channels and client in channels[channel_name]:
        for member in channels[channel_name]:
            if member != client:
                try:
                    member.send(f"[{channel_name}] {message}".encode('utf-8'))
                except:
                    member.close()
                    channels[channel_name].remove(member)
    else:
        client.send(f"You are not a member of channel '{channel_name}'.".encode('utf-8'))

def create_channel(client, channel_name, password=None):
    if channel_name not in channels:
        channels[channel_name] = []
        if password:
            private_channel_passwords[channel_name] = password
            client.send(f"Private channel '{channel_name}' has been created with a password.".encode('utf-8'))
        else:
            client.send(f"Channel '{channel_name}' has been created.".encode('utf-8'))
    else:
        client.send(f"Channel '{channel_name}' already exists.".encode('utf-8'))

def join_channel(client, channel_name, password=None):
    if channel_name not in channels:
        client.send(f"Channel '{channel_name}' does not exist.".encode('utf-8'))
        return
    if channel_name in private_channel_passwords:
        if password is None:
            client.send(f"Channel '{channel_name}' is private. Please enter the password to join.".encode('utf-8'))
            return
        if password != private_channel_passwords[channel_name]:
            client.send(f"Incorrect password for channel '{channel_name}'.".encode('utf-8'))
            return
    if client not in channels[channel_name]:
        channels[channel_name].append(client)
        user_channel[client] = channel_name  # Set the current channel for the user
        client.send(f"Joined channel '{channel_name}'.".encode('utf-8'))
        send_channel_message(client, channel_name, f"{usernames[client]} has joined the channel.")
    else:
        client.send(f"You are already in channel '{channel_name}'.".encode('utf-8'))

def leave_channel(client, channel_name):
    if channel_name in channels and client in channels[channel_name]:
        channels[channel_name].remove(client)
        user_channel[client] = None  # Remove the channel association
        client.send(f"Left channel '{channel_name}'.".encode('utf-8'))
        send_channel_message(client, channel_name, f"{usernames[client]} has left the channel.")
    else:
        client.send(f"You are not in channel '{channel_name}'.".encode('utf-8'))

def list_channels(client):
    if channels:
        channel_list = "Available channels:\n" + "\n".join(channels.keys())
    else:
        channel_list = "No channels available."
    client.send(channel_list.encode('utf-8'))

def start_server():
    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()
