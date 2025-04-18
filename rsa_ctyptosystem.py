"""
Rivest-Shamir-Adleman cryptosystem
"""

import random
import hashlib
import json
from math import gcd

class RSA:
    """
    Rivest-Shamir-Adleman cryptosystem implementation.
    """

    # -------------------- Prime Number Generation --------------------
    @staticmethod
    def generate_prime_numbers(min_value: int = 1000, \
                                max_value: int = 10000, number=2) -> tuple[int]:
        """  Generates <number> distinct prime numbers in the given range.

        Args:
            min_value (int, optional): Minimum value of prime numbers. Defaults to 1000.
            max_value (int, optional): Maximum value of prime numbers. Defaults to 1000.
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
    def encrypt(message: int, key: tuple[int, int]) -> int:
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
    def decrypt(ciphertext: int, key: tuple[int, int]) -> int:
        """ Decrypts a message using the RSA algorithm.

        Args:
            ciphertext (int): Encrypted message to decrypt.
            key (tuple[int, int]): Private key (n, d).

        Returns:
            int: Decrypted message.
        """

        n, d = key
        return RSA.endecrypt_message(ciphertext, d, n)

    # -------------------- Message Integrity --------------------
    @staticmethod
    def compute_hash(message: str) -> int:
        """ Computes a hash of the message.

        Args:
            message (str): Message to hash.

        Returns:
            int: Hash value as an integer.
        """
        # Use a shorter hash (first 8 bytes of SHA-256) to ensure it fits within RSA key modulus
        hash_obj = hashlib.sha256(message.encode())
        hash_bytes = hash_obj.digest()[:8]  # Use just first 8 bytes (64 bits)
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
        # Make sure hash is within the range of RSA modulus
        n, _ = private_key
        message_hash = message_hash % n
        return RSA.decrypt(message_hash, private_key)  # "Decrypt" the hash with private key to sign it

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
        # Make sure hash is within the range of RSA modulus
        n, _ = public_key
        message_hash = message_hash % n
        decrypted_signature = RSA.encrypt(signature, public_key)  # "Encrypt" the signature with public key
        return message_hash == decrypted_signature

    # -------------------- Symmetric Encryption and Decryption with Integrity --------------------
    @staticmethod
    def symmetric_encrypt_with_integrity(message: str, shared_secret: int, private_key: tuple[int, int]) -> str:
        """ Encrypts a message using a shared secret and adds a signature for integrity.

        Args:
            message (str): Message to encrypt.
            shared_secret (int): Shared secret for encryption.
            private_key (tuple[int, int]): Private key for signing.

        Returns:
            str: Encrypted message with signature.
        """
        # Sign the message first to ensure integrity
        signature = RSA.sign_message(message, private_key)
        
        # Create a data structure with message and signature
        # Convert signature to string to avoid precision issues with large integers in JSON
        data = {
            "message": message,
            "signature": str(signature)
        }
        
        # Convert to JSON string
        json_data = json.dumps(data)
        
        # Encrypt the entire package
        return RSA.symmetric_encrypt(json_data, shared_secret)

    @staticmethod
    def symmetric_decrypt_with_integrity(encrypted_message: str, shared_secret: int, 
                                        public_key: tuple[int, int]) -> tuple[str, bool]:
        """ Decrypts a message using a shared secret and verifies its integrity.

        Args:
            encrypted_message (str): Encrypted message with signature.
            shared_secret (int): Shared secret for decryption.
            public_key (tuple[int, int]): Public key for verification.

        Returns:
            tuple[str, bool]: Decrypted message and integrity verification result.
        """
        # Decrypt the message first
        try:
            decrypted_json = RSA.symmetric_decrypt(encrypted_message, shared_secret)
            
            # Parse the JSON data
            data = json.loads(decrypted_json)
            message = data["message"]
            # Convert signature back from string to integer
            signature = int(data["signature"])
            
            # Verify the signature
            is_valid = RSA.verify_signature(message, signature, public_key)
            
            return message, is_valid
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # If any errors occur during decryption or verification, integrity is compromised
            return f"Error: Message integrity compromised ({str(e)})", False

    # -------------------- Symmetric Encryption and Decryption --------------------
    @staticmethod
    def symmetric_encrypt(message: str, shared_secret: int) -> str:
        """ Encrypts a message using a shared secret.

        Args:
            message (str): Message to encrypt.
            shared_secret (int): Shared secret for encryption.

        Returns:
            str: Encrypted message.
        """

        return ''.join(chr((ord(char) + shared_secret) % 256) for char in message)

    @staticmethod
    def symmetric_decrypt(encrypted_message: str, shared_secret: int) -> str:
        """ Decrypts a message using a shared secret.

        Args:
            encrypted_message (str): Encrypted message to decrypt.
            shared_secret (int): Shared secret for decryption.

        Returns:
            str: Decrypted message.
        """

        return ''.join(chr((ord(char) - shared_secret) % 256) for char in encrypted_message)
