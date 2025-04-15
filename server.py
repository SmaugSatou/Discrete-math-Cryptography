"""
Server Module
"""

import socket
import threading
import secrets

from rsa_ctyptosystem import RSA

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
        self.shared_secrets = {}

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

            shared_secret = secrets.randbelow(10**6)
            encrypted_secret = RSA.encrypt(shared_secret, client_public_key)
            self.shared_secrets[client_socket] = shared_secret

            client_socket.send(str(encrypted_secret).encode())
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
                shared_secret = self.shared_secrets.get(client)

                encrypted_msg = RSA.symmetric_encrypt(msg, shared_secret)
                client.send(encrypted_msg.encode())

            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[server]: Error sending message to a client: {e}")
                self.remove_client(client)

    def handle_client(self, client_socket: socket.socket, addr: tuple[str, int]):
        """ Receives messages from a client and forwards them.

        Args:
            client_socket (socket.socket): The client socket.
            addr (Tuple[str, int]): The address of the connected client.
        """

        try:
            while True:
                encrypted_msg = client_socket.recv(1024).decode()

                if not encrypted_msg:
                    break

                if encrypted_msg == "!exit":
                    print(f"[server]: Client {addr} disconnected.")
                    break

                shared_secret = self.shared_secrets.get(client_socket)

                if shared_secret is None:
                    continue

                decrypted_msg = RSA.symmetric_decrypt(encrypted_msg, shared_secret)

                print(f"[server]: Received message from {addr}: {decrypted_msg}")

                self.broadcast(decrypted_msg, sender = client_socket)

        except (ConnectionResetError, BrokenPipeError, EOFError) as e:
            print(f"[server]: Client {addr} disconnected: {e}")

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
            self.shared_secrets.pop(client, None)
            client.close()

    def shutdown(self):
        """ Shuts down the server and closes all client connections. 
        """

        for client in self.clients:
            client.send("[server]: Server is shutting down.".encode())
            self.remove_client(client)

        self.s.close()

if __name__ == "__main__":
    s = Server(9001)
    s.start()
