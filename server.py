"""
Server Module
"""

import socket
import threading
import re

from rsa_cryptosystem import RSA

class Server:
    """
    TCP chat server with client handling and message broadcasting.
    """

    def __init__(self, port: int) -> None:
        """ Initializes the server.

        Args:
            port (int): The port on which the server will listen for connections.
        """

        self.lock = threading.Lock()
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.username_lookup = {}
        self.socket_lookup = {}
        self.public_keys = {}

        self.public_key, self.private_key = RSA.generate_key_pair()
        print("[server]: Server initialized with RSA keys for encryption and message integrity")
        print(f"[server]: RSA public key modulus: {self.public_key[0]}")

    def start(self):
        """ Starts the server and handles new connections.
        """

        try:
            self.s.bind((self.host, self.port))
            self.s.listen(100)

            print(f"[server]: Server started and listening on {self.host}:{self.port}")

            while True:
                c, addr = self.s.accept()
                threading.Thread(target = self.handle_new_client, args = (c, addr)).start()

        except (socket.error, OSError) as e:
            print(f"[server]: Socket error occurred: {e}")
        finally:
            self.shutdown()

    def handle_new_client(self, client_socket: socket.socket, addr: tuple[str, int]):
        """ Handles a new client connection.

        Args:
            client_socket (socket.socket): The socket object for the connected client.
            addr (Tuple[str, int]): The address of the connected client.
        """

        try:
            username = client_socket.recv(1024).decode()
            print(f"[server]: {username} tries to connect")

            self.username_lookup[client_socket] = username
            self.socket_lookup[username] = client_socket
            self.clients.append(client_socket)

            try:
                client_key_data = client_socket.recv(1024).decode()
                client_module, client_exponent = map(int, client_key_data.split(','))
            except ValueError:
                print(f"[server]: Incorrect format received. Data: {client_key_data}\n" +
                      "Valid format: <client_module,client_exponent>")
                self.remove_client(client_socket)
                return

            client_public_key = (client_module, client_exponent)
            self.public_keys[client_socket] = client_public_key

            server_key_data = f"{self.public_key[0]},{self.public_key[1]}"
            client_socket.send(server_key_data.encode())

            print(f"[server]: Client {username} connected " +\
                  f"with RSA public key (modulus: {client_module})")
            self.broadcast(f'[server]: new person has joined: {username}', sender=client_socket)

            threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

        except (ValueError, socket.error, OSError) as e:
            print(f"[server]: Error handling new client: {e}")
            self.remove_client(client_socket)

    def broadcast(self, msg: str, sender: socket = None):
        """ Sends a message to all connected clients except the sender.

        Args:
            msg (str): The message to send.
            sender (Optional[socket.socket]): The client socket that sent the message.
        """

        for client in self.clients:
            if client == sender:
                continue

            try:
                client_public_key = self.public_keys.get(client)
                if client_public_key is None:
                    continue

                encrypted_msg = RSA.encrypt_with_integrity(
                    msg, client_public_key, self.private_key
                )
                client.send(encrypted_msg.encode())

            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[server]: Error sending message to a client: {e}")
                self.remove_client(client)

    def send_private_message(self, message: str, recipient_username: str, sender: socket.socket):
        """ Sends a private message to a specific client.

        Args:
            message (str): The private message to send.
            recipient_username (str): The username of the recipient.
            sender (socket.socket): The client socket that sent the message.
        """

        recipient_socket = self.socket_lookup.get(recipient_username)

        if recipient_socket:
            try:
                recipient_public_key = self.public_keys.get(recipient_socket)
                if recipient_public_key is None:
                    return

                private_msg = f"[private] {self.username_lookup[sender]}: {message}"

                encrypted_msg = RSA.encrypt_with_integrity(
                    private_msg, recipient_public_key, self.private_key
                )

                recipient_socket.send(encrypted_msg.encode())

                print(f"[server]: Private message from {self.username_lookup[sender]} " + \
                       f"to {self.username_lookup[recipient_socket]}: {message}")
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[server]: Error sending private message to {recipient_username}: {e}")
                self.remove_client(recipient_socket)
        else:
            print(f"[server]: Private message recipient '{recipient_username}' not found.")

    def handle_client(self, client_socket: socket.socket, addr: tuple[str, int]):
        """ Receives messages from a client and forwards them.

        Args:
            client_socket (socket.socket): The client socket.
            addr (Tuple[str, int]): The address of the connected client.
        """

        try:
            while True:
                encrypted_msg = client_socket.recv(4096).decode()

                if not encrypted_msg:
                    break

                if encrypted_msg == "!exit":
                    print(f"[server]: Client {addr} disconnected.")
                    break

                client_public_key = self.public_keys.get(client_socket)

                if client_public_key is None:
                    continue

                decrypted_msg, is_valid = RSA.decrypt_with_integrity(
                    encrypted_msg, self.private_key, client_public_key
                )

                if not is_valid:
                    print(f"[server WARNING]: Received message with invalid integrity from {addr}!")
                    print(f"Message content: {decrypted_msg}")
                    continue

                if private_message_match := re.match(r"^@(\w+)\s+(.*)", decrypted_msg):
                    recipient_username = private_message_match.group(1)
                    private_message = private_message_match.group(2)

                    self.send_private_message(private_message, recipient_username, \
                                              sender = client_socket)
                else:
                    username = self.username_lookup.get(client_socket, f"User{addr}")
                    full_message = f"{username}: {decrypted_msg}"
                    self.broadcast(full_message, sender=client_socket)
                    print(f"[server]: Received message from {addr}: {decrypted_msg}")

        except (ConnectionResetError, BrokenPipeError, EOFError) as e:
            print(f"[server]: Client {addr} disconnected: {e}")
        except Exception as e:
            print(f"[server]: Error handling client message: {e}")

        self.remove_client(client_socket)
        self.broadcast(f"[server]: Client {addr} disconnected.")

    def remove_client(self, client: socket.socket):
        """ Removes a client from the server and closes the connection.

        Args:
            client_socket (socket.socket): The client socket to remove.
        """

        if client in self.clients:
            self.clients.remove(client)
            self.username_lookup.pop(client, None)
            self.public_keys.pop(client, None)
            client.close()

    def shutdown(self):
        """ Shuts down the server and closes all client connections. 
        """

        for client in self.clients:
            try:
                client.send("[server]: Server is shutting down.".encode())
            except:
                pass
            self.remove_client(client)

        self.s.close()

if __name__ == "__main__":
    s = Server(9001)
    s.start()
