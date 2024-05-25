'''
Authors:
Khadija Al Balushi (133556)
Quds Al Breiki (133343)
Omamah Al Muqarshi (129590)

Server code: 

establishes a safe chat server on which numerous clients can join,
verify their identities, and exchange messages. Each client is given a nickname,
and user credentials are stored in a specified dictionary for authentication. 
AES is used by the server to encrypt and decrypt messages,
guaranteeing safe transmission. Additionally, 
it prevents tampering by using SHA-256 checksums to confirm the 
integrity of communications. Threads are used by the server to manage
several clients at once, and locks guarantee thread-safe access to
shared resources. Before enabling them to transmit messages, the
server checks the encrypted credentials that clients submit during 
authentication. This configuration guarantees dependable and safe 
communication within the chat program.

'''

import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import secrets
import threading

#dummy database of username-password pairs
USER_DATABASE = {
    "omamah": "1111",
    "quds": "2222",
    "khadija": "3333"
}

#dictionary to store client nicknames
client_nicknames = {}
#lock for thread-safe access to client_nicknames
nicknames_lock = threading.Lock()

def authenticate(username, password):
    #authenticate the user based on username and password.
    if username in USER_DATABASE and USER_DATABASE[username] == password:
        return True
    return False

def decrypt_message(encrypted_message, key):
    #decrypt an AES-encrypted message using the provided key.
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, AES.block_size)
    return unpadded_message.decode()

def encrypt_message(message, key):
    #encrypt a message using AES encryption with the provided key.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def calculate_checksum(message):
    #calculate SHA-256 checksum of a message.
    return hashlib.sha256(message).hexdigest().encode()

def broadcast_message(sender_nickname, message):
    #broadcast a message to all connected clients except the sender.
    with nicknames_lock:
        for client_socket, nickname in client_nicknames.items():
            if nickname != sender_nickname:
                try:
                    client_socket.send(message)
                except Exception as e:
                    print("Error sending message to client '{}':".format(nickname), e)

def handle_client(client_socket):
    #handle communication with a connected client.
    try:
        #send the encryption key to the client
        client_socket.send(key)

        #receive encrypted username and password from client
        encrypted_username = client_socket.recv(1024)
        encrypted_password = client_socket.recv(1024)

        #extract message and checksum from received data
        received_username = encrypted_username[:-64]
        received_checksum_username = encrypted_username[-64:]
        received_password = encrypted_password[:-64]
        received_checksum_password = encrypted_password[-64:]

        #calculate checksums for received data
        checksum_username = calculate_checksum(received_username)
        checksum_password = calculate_checksum(received_password)

        #verify checksums
        if checksum_username == received_checksum_username and checksum_password == received_checksum_password:
            #decrypt username and password
            username = decrypt_message(received_username, key)
            password = decrypt_message(received_password, key)

            #authenticate user
            if authenticate(username, password):
                client_socket.send(b"Authentication successful!")
                nickname = client_socket.recv(1024).decode()
                with nicknames_lock:
                    client_nicknames[client_socket] = nickname
                print("Client '{}' authenticated with nickname '{}'".format(username, nickname))
            else:
                client_socket.send(b"Authentication failed! Closing connection.")
                client_socket.close()
                return
        else:
            client_socket.send(b"Checksum verification failed! Closing connection.")
            client_socket.close()
            return

        #handle client messages
        while client_socket in client_nicknames:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("Empty message received from client '{}'. Closing connection.".format(client_nicknames[client_socket]))
                client_socket.close()
                with nicknames_lock:
                    del client_nicknames[client_socket]
                break

            received_message = encrypted_message[:-64]
            received_checksum_message = encrypted_message[-64:]

            checksum_message = calculate_checksum(received_message)
            if checksum_message == received_checksum_message:
                message = decrypt_message(received_message, key)
                full_message = "{}: {}".format(client_nicknames[client_socket], message)
                encrypted_full_message = encrypt_message(full_message, key)
                broadcast_message(client_nicknames[client_socket], encrypted_full_message + calculate_checksum(encrypted_full_message))
                print("Received message from '{}': {}".format(client_nicknames[client_socket], message))
            else:
                print("Checksum verification failed for message from client '{}'".format(client_nicknames[client_socket]))

    except Exception as e:
        print("Error handling client:", e)
    finally:
        client_socket.close()
        with nicknames_lock:
            if client_socket in client_nicknames:
                del client_nicknames[client_socket]

def main():
    #set up the server and handle incoming client connections.
    host = '127.0.0.1'
    port = 12345
    global key
    key = secrets.token_bytes(16)

    #create and bind the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("Server listening on {}:{}".format(host, port))
    print("Generated Key:", key.hex())

    while True:
        #accept incoming client connections
        client_socket, addr = server_socket.accept()
        print("Connection from", addr)
        #start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    main()
