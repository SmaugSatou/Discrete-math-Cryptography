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

        print(f"[server]: Server started and listening on {self.host}:{self.port}")

        # generate keys ...

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()

            print(f"[server]: {username} tries to connect")

            self.broadcast(f'[server]: new person has joined: {username}')
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

            try:
                client.send(msg.encode())
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[server]: Error sending message to a client: {e}")
                self.remove_client(client)

    def handle_client(self, c: socket, addr):
        """ Receives messages from a client and forwards them.

        Args:
            c (socket.socket): Client socket.
            addr: Client address (host, port).
        """

        try:
            while True:
                msg = c.recv(1024)

                if msg.decode().lower() == "!exit":
                    print(f"[server]: Client {addr} disconnected.")
                    break

                for client in self.clients:
                    if client != c:
                        try:
                            client.send(msg)
                        except (ConnectionResetError, BrokenPipeError) as e:
                            print(f"[server]: Error sending message to a client: {e}")
                            self.remove_client(client)
        except (ConnectionResetError, BrokenPipeError, EOFError) as e:
            print(f"[server]: Client {addr} disconnected: {e}")

        self.remove_client(c)
        self.broadcast(f"[server]: Client {addr} disconnected.")

    def remove_client(self, client):
        """ Removes a client from the server and closes the connection. 
        """

        if client in self.clients:
            self.clients.remove(client)
            client.close()

if __name__ == "__main__":
    s = Server(9001)
    s.start()
