"""
Server Module
"""

import socket
import threading

class Server:
    """
    TCP chat server with client handling and message broadcasting.
    """

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def start(self):
        """ Starts the server and handles new connections.
        """

        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()

            print(f"{username} tries to connect")

            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client

            # ...

            # encrypt the secret with the clients public key

            # ...

            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        """ Sends a message to all connected clients.

        Args:
            msg (str): Message to send.
        """

        for client in self.clients:

            # encrypt the message

            # ...

            client.send(msg.encode())

    def handle_client(self, c: socket, addr):
        """ Receives messages from a client and forwards them.

        Args:
            c (socket.socket): Client socket.
            addr: Client address (host, port).
        """

        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()
