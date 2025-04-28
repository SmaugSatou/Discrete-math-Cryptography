"""
Rivest-Shamir-Adleman cryptosystem
"""

import random
import hashlib
import json
import base64
from math import gcd

class RSA:
    """
    Rivest-Shamir-Adleman cryptosystem implementation.
    """

    # -------------------- Prime Number Generation --------------------
    @staticmethod
    def generate_prime_numbers(min_value: int = 10000, \
                                max_value: int = 50000, number=2) -> tuple[int]:
        """  Generates <number> distinct prime numbers in the given range.

        Args:
            min_value (int, optional): Minimum value of prime numbers. Defaults to 10000.
            max_value (int, optional): Maximum value of prime numbers. Defaults to 50000.
            number (int, optional): <number> of prime numbers to return. Defaults to 2.

        Returns:
            tuple[int]: Prime numbers in the given range.
        """

        def is_prime(number: int) -> bool:
            """ Checks if a number is prime.

            Args:
                number (int): Number to check.

            Returns:
                bool: True if prime, False otherwise.
            """

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

        primes = [p for p in range(min_value, max_value) if is_prime(p)]

        if not primes:
            raise ValueError("No prime number in the given interval!")

        return random.sample(primes, number)

    # -------------------- Modular Arithmetic --------------------
    @staticmethod
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        """ Computes the Extended Euclidean Algorithm.

        Args:
            a (int): First number.
            b (int): Second number.

        Returns:
            tuple[int, int, int]: [gcd, x, y] where gcd is the greatest common divisor of a and b.
        """

        if a == 0:
            return b, 0, 1

        gcd_value, x1, y1 = RSA.extended_gcd(b % a, a)

        return gcd_value, y1 - (b // a) * x1, x1

    @staticmethod
    def modular_inverse(a: int, module: int) -> int:
        """ Computes the modular inverse.

        Args:
            a (int): Number to find the inverse of.
            module (int): Moudulus.

        Returns:
            int: Modular inverse of given number under the given modulus.
        """

        gcd_value, x, _ = RSA.extended_gcd(a, module)

        if gcd_value != 1:
            raise ValueError("Modular inverse does not exist!")

        return x % module

    # -------------------- Key Generation --------------------
    @staticmethod
    def generate_key_pair() -> tuple[tuple[int, int], tuple[int, int]]:
        """ Generates an RSA public-private key pair.

        Returns:
            tuple[tuple[int, int], tuple[int, int]]: Public key (n, e) and private key (n, d).
        """

        prime_1, prime_2 = RSA.generate_prime_numbers()
        module = prime_1 * prime_2
        totient = (prime_1 - 1) * (prime_2 - 1)

        public_exponent = random.randrange(3, totient, 2)
        while gcd(public_exponent, totient) != 1:
            public_exponent = random.randrange(3, totient, 2)

        private_exponent = RSA.modular_inverse(public_exponent, totient)

        return (module, public_exponent), (module, private_exponent)

    # -------------------- RSA Encryption and Decryption --------------------
    @staticmethod
    def endecrypt_message(message: int, key: int, module: int) -> int:
        """ Endecrypts or decrypts a message using the RSA algorithm.

        Args:
            message (int): Message to encrypt or decrypt.
            key (int): Public or private exponent.
            n (int): modulus.

        Returns:
            int: Encrypted or decrypted message.
        """

        res = 1

        message = message % module

        if message == 0:
            return 0

        while key > 0:
            if key & 1 == 1:
                res = (res * message) % module

            key = key >> 1
            message = (message * message) % module

        return res

    @staticmethod
    def encrypt_int(message: int, key: tuple[int, int]) -> int:
        """ Encrypts a message using the RSA algorithm.

        Args:
            message (int): Message to encrypt.
            key (tuple[int, int]): Public key (n, e).

        Returns:
            int: Encrypted message.
        """

        n, e = key
        return RSA.endecrypt_message(message, e, n)

    @staticmethod
    def decrypt_int(ciphertext: int, key: tuple[int, int]) -> int:
        """ Decrypts a message using the RSA algorithm.

        Args:
            ciphertext (int): Encrypted message to decrypt.
            key (tuple[int, int]): Private key (n, d).

        Returns:
            int: Decrypted message.
        """

        n, d = key
        return RSA.endecrypt_message(ciphertext, d, n)

    # -------------------- Text Encryption and Decryption with RSA --------------------
    @staticmethod
    def encrypt_text(message: str, key: tuple[int, int]) -> str:
        """ Encrypts a text message using RSA by processing it in chunks.
        
        Args:
            message (str): The text message to encrypt.
            key (tuple[int, int]): Public key (n, e).
            
        Returns:
            str: Base64-encoded encrypted message.
        """
        n, _ = key
        max_bytes = (n.bit_length() - 1) // 8 - 1

        if max_bytes < 1:
            raise ValueError("Key size too small for text encryption")

        message_bytes = message.encode('utf-8')
        chunks = [message_bytes[i:i+max_bytes] for i in range(0, len(message_bytes), max_bytes)]

        encrypted_chunks = []
        for chunk in chunks:
            chunk_int = int.from_bytes(chunk, byteorder='big')
            encrypted_int = RSA.encrypt_int(chunk_int, key)
            encrypted_chunks.append(encrypted_int)

        encrypted_json = json.dumps(encrypted_chunks)
        return base64.b64encode(encrypted_json.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt_text(encrypted_message: str, key: tuple[int, int]) -> str:
        """ Decrypts a text message encrypted with RSA.
        
        Args:
            encrypted_message (str): Base64-encoded encrypted message.
            key (tuple[int, int]): Private key (n, d).
            
        Returns:
            str: Decrypted text message.
        """
        try:
            json_data = base64.b64decode(encrypted_message.encode('utf-8')).decode('utf-8')
            encrypted_chunks = json.loads(json_data)

            decrypted_chunks = []
            for encrypted_int in encrypted_chunks:
                decrypted_int = RSA.decrypt_int(encrypted_int, key)
                bytes_required = (decrypted_int.bit_length() + 7) // 8
                decrypted_bytes = decrypted_int.to_bytes(bytes_required, byteorder='big')
                decrypted_chunks.append(decrypted_bytes)

            decrypted_message = b''.join(decrypted_chunks)
            return decrypted_message.decode('utf-8')

        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            return f"Error decrypting message: {str(e)}"

    # -------------------- Message Integrity --------------------
    @staticmethod
    def compute_hash(message: str) -> int:
        """ Computes a hash of the message.

        Args:
            message (str): Message to hash.

        Returns:
            int: Hash value as an integer.
        """
        hash_obj = hashlib.sha256(message.encode())
        hash_bytes = hash_obj.digest()[:8]  # Use first 8 bytes (64 bits)
        return int.from_bytes(hash_bytes, byteorder='big')

    @staticmethod
    def sign_message(message: str, private_key: tuple[int, int]) -> int:
        """ Signs a message using the private key.

        Args:
            message (str): Message to sign.
            private_key (tuple[int, int]): Private key (n, d).

        Returns:
            int: Digital signature.
        """
        message_hash = RSA.compute_hash(message)
        n, _ = private_key
        message_hash = message_hash % n

        # "Decrypt" the hash with private key to sign it
        return RSA.decrypt_int(message_hash, private_key)

    @staticmethod
    def verify_signature(message: str, signature: int, public_key: tuple[int, int]) -> bool:
        """ Verifies a message signature.

        Args:
            message (str): Original message.
            signature (int): Signature to verify.
            public_key (tuple[int, int]): Public key (n, e).

        Returns:
            bool: True if signature is valid, False otherwise.
        """
        message_hash = RSA.compute_hash(message)
        n, _ = public_key
        message_hash = message_hash % n

        # "Encrypt" the signature with public key
        decrypted_signature = RSA.encrypt_int(signature, public_key)
        return message_hash == decrypted_signature

    # -------------------- Message Encryption with Integrity --------------------
    @staticmethod
    def encrypt_with_integrity(message: str, \
                               recipient_public_key: tuple[int, int], \
                               sender_private_key: tuple[int, int]) -> str:
        """ Encrypts a message and adds a signature for integrity.

        Args:
            message (str): Message to encrypt.
            recipient_public_key (tuple[int, int]): Recipient's public key.
            sender_private_key (tuple[int, int]): Sender's private key.

        Returns:
            str: Encrypted message with signature.
        """
        signature = RSA.sign_message(message, sender_private_key)

        data = {
            "message": message,
            "signature": str(signature)
        }

        json_data = json.dumps(data)
        return RSA.encrypt_text(json_data, recipient_public_key)

    @staticmethod
    def decrypt_with_integrity(encrypted_message: str, \
                               recipient_private_key: tuple[int, int], \
                              sender_public_key: tuple[int, int]) -> tuple[str, bool]:
        """ Decrypts a message and verifies its integrity.

        Args:
            encrypted_message (str): Encrypted message with signature.
            recipient_private_key (tuple[int, int]): Recipient's private key.
            sender_public_key (tuple[int, int]): Sender's public key.

        Returns:
            tuple[str, bool]: Decrypted message and integrity verification result.
        """
        try:
            decrypted_json = RSA.decrypt_text(encrypted_message, recipient_private_key)

            data = json.loads(decrypted_json)
            message = data["message"]
            signature = int(data["signature"])

            is_valid = RSA.verify_signature(message, signature, sender_public_key)

            return message, is_valid
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return f"Error: Message integrity compromised ({str(e)})", False
