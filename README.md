Overview

This project implements a secure chat server and client system that allows multiple clients to communicate safely. The system uses AES encryption to ensure message confidentiality, SHA-256 checksums to verify message integrity, and a robust authentication mechanism to validate user credentials. The server handles multiple clients concurrently using multithreading.

Authors
Khadija Al Balushi (133556)
Quds Al Breiki (133343)
Omamah Al Muqarshi (129590)

Features
- User Authentication: Validates clients using a username and password.
- Encryption: Secures messages with AES encryption.
- Integrity Verification: Ensures message integrity using SHA-256 checksums.
- Multithreading: Handles multiple clients simultaneously without compromising performance.

Installation

Prerequisites
Python 3.x installed on your system.

Usage Instructions

Server
Setup: Ensure all dependencies are installed, particularly pycryptodome for cryptographic functions.
pip install pycryptodome

Run the Server:
python server.py

Client
Setup: Ensure all dependencies are installed, particularly pycryptodome for cryptographic functions.
pip install pycryptodome

Run the Client:
python client.py

Authentication:
Enter the username and password when prompted. Valid credentials are stored in the server's USER_DATABASE.
Nickname and Messaging:
After successful authentication, enter a nickname.
Send messages by typing in the input and pressing Enter.
Type "exit" to leave the chat.


Notes

- Ensure the server is running before starting the client.
- Enter valid credentials to authenticate and start chatting.
- To exit the chat, type exit in the client.

License
This project is licensed under the MIT License - see the LICENSE file for details.

"# secured-distributed-system" 
"# secured-distributed-system" 
# Projects
# Projects
# Secured-Communication-System
# SecuredCommunicationSystem
# SecuredCommunicationSystem
# project
