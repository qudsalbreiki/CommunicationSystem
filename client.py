'''
Authors:
Khadija Al Balushi (133556)
Quds Al Breiki (133343)
Omamah Al Muqarshi (129590)

Client code:

establishing a secure chat server client. 
After establishing a connection with the 
server and verifying its identity with a password,
the client enables users to send and receive encrypted messages.
The client gets an AES encryption key from the server when 
it connects. The user's credentials are encrypted and sent
for verification together with their SHA-256 checksums.
The user can create a nickname and send messages if their 
authentication is successful. To guarantee integrity, every
message is checksummed and encrypted. To keep the main thread
responsive to user interaction, a secondary thread receives 
and decrypts messages from the server. Secure and validated 
connectivity with the server is ensured by this configuration.
if the client want to exit the chat, they can type 'exit' .

'''
import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import threading

def encrypt_message(message, key):
    #encrypt a message using AES encryption with the provided key.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def calculate_checksum(message):
    #calculate SHA-256 checksum of a message.
    return hashlib.sha256(message).hexdigest().encode()

def decrypt_message(encrypted_message, key):
    #decrypt an AES-encrypted message using the provided key.
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message)
        unpadded_message = unpad(decrypted_message, AES.block_size)
        return unpadded_message.decode()
    except ValueError:
        print("Received encrypted message:", encrypted_message)
        raise

def receive_messages(client_socket, key):
    #receive and decrypt messages from the server.
    while True:
        try:
            response = client_socket.recv(1024)
            if not response:
                break
            received_message = response[:-64]
            received_checksum = response[-64:]

            checksum = calculate_checksum(received_message)
            if checksum == received_checksum:
                decrypted_response = decrypt_message(received_message, key)
                print(decrypted_response)
            else:
                print("Checksum verification failed for received message.")
        except ConnectionResetError:
            print("Server closed the connection.")
            break

def main():
    #set up the client, authenticate, and handle message sending and receiving.
    host = '127.0.0.1'
    port = 12345

    #connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    #receive encryption key from the server
    key = client_socket.recv(1024)

    #input username and password for authentication
    username = input("Enter username: ")
    password = input("Enter password: ")

    #encrypt username and password
    encrypted_username = encrypt_message(username, key)
    encrypted_password = encrypt_message(password, key)

    #calculate checksums
    checksum_username = calculate_checksum(encrypted_username)
    checksum_password = calculate_checksum(encrypted_password)

    #send encrypted credentials and checksums to the server
    client_socket.send(encrypted_username + checksum_username)
    client_socket.send(encrypted_password + checksum_password)

    #receive authentication response
    response = client_socket.recv(1024)
    print(response.decode())

    if response == b"Authentication successful!":
        #input nickname after successful authentication
        nickname = input("Enter your nickname: ")
        client_socket.send(nickname.encode())

        #start a thread to receive messages
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, key))
        receive_thread.start()

        #send messages to the server
        while True:
            message = input()
            if message.strip():
                if message.lower() == "exit":
                    client_socket.close()
                    break
                encrypted_message = encrypt_message(message, key)
                checksum_message = calculate_checksum(encrypted_message)
                client_socket.send(encrypted_message + checksum_message)
            else:
                print("Message cannot be empty.")

if __name__ == "__main__":
    main()
