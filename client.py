"""
Client Module
"""

import socket
import threading
import random

from rsa_ctyptosystem import RSA

class Client:
    """
    TCP client for sending/receiving messages.
    """

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.client_socket = None
        self.public_key = None
        self.private_key = None
        self.shared_secret = None

    def init_connection(self):
        """ Connects to server and starts I/O threads.
        """

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.client_socket.connect((self.server_ip, self.port))
            print(f"[client]: Connected to server at {self.server_ip}:{self.port}")
        except (ConnectionRefusedError, socket.gaierror, socket.timeout) as e:
            print("[client]: Could not connect to server: ", e)
            return

        self.client_socket.send(self.username.encode())

        self.public_key, self.private_key = RSA.generate_key_pair()

        client_key_data = f"{self.public_key[0]},{self.public_key[1]}"
        self.client_socket.send(client_key_data.encode())

        encrypted_secret = int(self.client_socket.recv(1024).decode())
        self.shared_secret = RSA.decrypt(encrypted_secret, self.private_key)

        print(f"[client]: Shared secret established: {self.shared_secret}")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """ Handles incoming messages.
        """

        while True:
            try:
                encrypted_message = self.client_socket.recv(1024).decode()

                if not encrypted_message:
                    break

                decrypted_message = RSA.symmetric_decrypt(encrypted_message, self.shared_secret)
                print(decrypted_message)

            except (ConnectionResetError, BrokenPipeError):
                print("[client]: Connection lost.")
                break

    def write_handler(self):
        """ Handles outgoing messages.
        """

        try:
            while True:
                message = input()

                if message.lower() == "!exit":
                    print("[client]: Disconnecting...")
                    self.client_socket.send(b'!exit')
                    break

                encrypted_message = RSA.symmetric_encrypt(message, self.shared_secret)
                self.client_socket.send(encrypted_message.encode())

        except EOFError:
            print("[client]: Input stream closed. Disconnecting...")
            self.client_socket.send(b'!exit')

        print("[client]: Connection closed.")

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, f"user_{random.randint(1, 10000)}")
    cl.init_connection()
