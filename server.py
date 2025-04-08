"""
Server Module
"""

import socket
import threading

import random
from math import gcd

class RSA:
    """
    Rivest-Shamir-Adleman cryptosystem implementation.
    """

    @staticmethod
    def generate_prime_numbers(min_value: int = 1000, max_value: int = 10000, \
                                    number = 2) -> tuple[int]:
        """ Generates <number> distinct prime numbers in given range.

        Args:
            min_value (int, optional): Minimum value of prime numbers. Defaults to 1000.
            max_value (int, optional): Maximum value of prime numbers. Defaults to 10000.

        Returns:
            tuple[int]: Prime numbers.
        """

        def is_prime(number: int):
            if number < 2:
                return False

            if number == 2:
                return True

            if number % 2 == 0:
                return False

            for i in range(3, int(number**0.5) + 1, 2):
                if number % i == 0:
                    return False

            return True

        primes = []

        for possible_prime in range(min_value, max_value):
            if is_prime(possible_prime):
                primes.append(possible_prime)

        if not primes:
            raise ValueError("No prime number in a given interval!")

        return random.sample(primes, number)

    @staticmethod
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        """ Computes the Extended Euclidean Algorithm.

        Args:
            a (int): First number.
            b (int): Second number.

        Returns:
            tuple[int, int, int]: [GCD value, first coefficient, second coefficient]
        """

        if a == 0:
            return (b, 0, 1)

        gcd_value, x1, y1 = RSA.extended_gcd(b % a, a)
        return (gcd_value, y1 - (b // a) * x1, x1)

    @staticmethod
    def modular_inverse(a: int, module: int) -> int:
        """ Computes the modular inverse.

        Args:
            a (int): The number to invert.
            module (int): The modulus.

        Returns:
            int: The modular inverse.
        """

        gcd_value, x, _ = RSA.extended_gcd(a, module)

        if gcd_value != 1:
            raise ValueError('Modular inverse does not exist!')

        return x % module

    @staticmethod
    def generate_key_pair() -> tuple[tuple[int, int], tuple[int, int]]:
        """ Generates an RSA public-private key pair.

        Returns:
             tuple[tuple[int, int], tuple[int, int]]: [Public key pair, Private key pair]
        """

        prime_1, prime_2 = RSA.generate_prime_numbers()

        module = prime_1 * prime_2
        totient = (prime_1 - 1) * (prime_2 - 1)

        public_exponent = random.randrange(3, totient, 2)
        while gcd(public_exponent, totient) != 1:
            public_exponent = random.randrange(3, totient, 2)

        private_exponent = RSA.modular_inverse(public_exponent, totient)

        public_key = (module, public_exponent)
        private_key = (module, private_exponent)

        return public_key, private_key

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
