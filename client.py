"""
Client Module
"""

import socket
import threading
import random

from rsa_cryptosystem import RSA

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
        self.server_public_key = None

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

        server_key_data = self.client_socket.recv(1024).decode()
        server_module, server_exponent = map(int, server_key_data.split(','))
        self.server_public_key = (server_module, server_exponent)

        print(f"[client]: RSA keys exchanged. Public key modulus: {self.public_key[0]}")
        print("[client]: Message integrity verification enabled")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """ Handles incoming messages.
        """

        while True:
            try:
                encrypted_message = self.client_socket.recv(4096).decode()

                if not encrypted_message:
                    break

                decrypted_message, is_valid = RSA.decrypt_with_integrity(
                    encrypted_message, self.private_key, self.server_public_key
                )

                if is_valid:
                    print(decrypted_message)
                else:
                    print("[client WARNING]: Received message with invalid " +\
                           "integrity - may have been tampered with!")
                    print(f"Message content: {decrypted_message}")

            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[client]: Connection lost: {e}")
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

                encrypted_message = RSA.encrypt_with_integrity(
                    message, self.server_public_key, self.private_key
                )
                self.client_socket.send(encrypted_message.encode())

        except EOFError:
            print("[client]: Input stream closed. Disconnecting...")
            self.client_socket.send(b'!exit')
        except Exception as e:
            print(f"[client]: Error in write handler: {e}")

        print("[client]: Connection closed.")

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, f"user_{random.randint(1, 10000)}")
    cl.init_connection()
