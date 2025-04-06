"""
Client Module
"""

import socket
import threading

class Client:
    """
    TCP client for sending/receiving messages.
    """

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.client_socket = None

    def init_connection(self):
        """ Connects to server and starts I/O threads.
        """

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.client_socket.connect((self.server_ip, self.port))
        except (ConnectionRefusedError, socket.gaierror, socket.timeout) as e:
            print("[client]: could not connect to server: ", e)
            return

        self.client_socket.send(self.username.encode())

        # create key pairs

        # exchange public keys

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """ Handles incoming messages.
        """

        while True:
            message = self.client_socket.recv(1024).decode()

            # decrypt message with the secrete key

            # ...


            print(message)

    def write_handler(self):
        """ Handles outgoing messages.
        """

        while True:
            message = input()

            # encrypt message with the secrete key

            # ...

            self.client_socket.send(message.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
