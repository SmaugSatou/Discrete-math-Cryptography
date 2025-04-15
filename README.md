# Discrete-math-Cryptography

## Project Overview

This project is a practical implementation of secure message exchange using the **RSA algorithm**.

The goal is to demonstrate the core principles of cryptography (modular arithmetic, prime number generation, public/private key cryptosystems) and their integration into a client-server architecture that supports encrypted communication.

## Implementation Details

### RSA Cryptosystem

The `rsa_ctyptosystem.py` module implements the RSA cryptosystem and provides the following functionality:

- **Key Generation**:
  - Two large prime numbers `p` and `q` are generated within a specified range.
  - The modulus `n = p * q` is calculated.
  - Euler’s totient function `phi = (p - 1)(q - 1)` is computed.
  - A public exponent `e` is chosen such that it is coprime with `phi`.
  - The private exponent `d` is calculated as the modular inverse of `e` modulo `phi`.

- **Encryption and Decryption**:
  - Messages are encrypted using the public key `(e, n)` with the formula:  
    `cipher = (message^e) mod n`.
  - Encrypted messages are decrypted using the private key `(d, n)` with the formula:  
    `message = (cipher^d) mod n`.

- **Symmetric Encryption**:
  - A shared secret is exchanged using RSA encryption.
  - Messages are encrypted and decrypted using a simple symmetric cipher based on character shifts.

### Server

The `server.py` script implements a TCP server that facilitates secure communication between clients. Key features include:

- **Client Connection Handling**:
  - Accepts incoming client connections and receives their username and public RSA key.
  - Generates a random symmetric key (shared secret) for each client.
  - Encrypts the shared secret using the client’s public RSA key and sends it to the client.

- **Message Broadcasting**:
  - Decrypts incoming messages from clients using their shared secret.
  - Re-encrypts the message with the shared secret of each recipient and broadcasts it to all connected clients except the sender.

### Client

The `client.py` script implements a TCP client for secure communication with the server. Key features include:

- **Connection Initialization**:
  - Connects to the server and sends the user’s username and public RSA key.
  - Receives the encrypted shared secret from the server and decrypts it using the private RSA key.

- **Message Encryption and Decryption**:
  - Outgoing messages are encrypted using the shared secret before being sent to the server.
  - Incoming messages are decrypted using the shared secret and displayed to the user.

- **Real-Time Communication**:
  - Supports real-time message exchange using separate threads for reading and writing messages.

### Message Integrity

---

## Task Distribution

**Roman Prokhorov**:
- Implemented the RSA cryptosystem module, including key generation, encryption, and decryption.
- Wrote the server and client logic for a TCP-based chat system.
- Integrated encryption and decryption into the real-time chat system.

**Mykhailo Rykhalskyi**:

---

## Getting Started

### Clone the repository:
```bash
git clone https://github.com/SmaugSatou/Discrete-math-Cryptography.git
```

### Start the server:
```bash
python server.py
```

### Connect a client (Use another terminal window):
```bash
python client.py
```