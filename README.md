# Discrete-math-Cryptography

## Project Overview

This project is a practical implementation of secure message exchange using the **RSA algorithm**.

The goal is to demonstrate the core principles of cryptography (modular arithmetic, prime number generation, public/private key cryptosystems) and their integration into a client-server architecture that supports encrypted communication.

## Implementation Details

### RSA Cryptosystem

The `rsa_ctyptosystem.py` module implements the RSA cryptosystem and provides the following functionality:

- **Key Generation**:
  - Two large prime numbers `p` and `q` are generated within a specified range (10,000-50,000).
  - The modulus `n = p * q` is calculated.
  - Euler's totient function `phi = (p - 1)(q - 1)` is computed.
  - A public exponent `e` is chosen such that it is coprime with `phi`.
  - The private exponent `d` is calculated as the modular inverse of `e` modulo `phi`.

- **Pure RSA Encryption and Decryption**:
  - Messages are encrypted using the recipient's public key `(e, n)` with the formula:  
    `cipher = (message^e) mod n`.
  - Encrypted messages are decrypted using the recipient's private key `(d, n)` with the formula:  
    `message = (cipher^d) mod n`.
  - For longer messages, the system splits the content into chunks that fit within the RSA key's capacity.
  - Each chunk is encrypted separately and combined to form the complete encrypted message.

### Server

The `server.py` script implements a TCP server that facilitates secure communication between clients. Key features include:

- **Client Connection Handling**:
  - Accepts incoming client connections and receives their username and public RSA key.
  - Sends the server's public RSA key to the client for encryption and verification.
  - Establishes a secure communication channel based purely on RSA encryption.

- **Message Broadcasting**:
  - Encrypts outgoing messages directly with each recipient's public RSA key.
  - Signs each message with the server's private key to ensure authenticity.
  - Verifies the integrity of incoming messages using clients' public keys.

### Client

The `client.py` script implements a TCP client for secure communication with the server. Key features include:

- **Connection Initialization**:
  - Connects to the server and exchanges public RSA keys.
  - Establishes a secure communication channel for sending and receiving messages.

- **Message Encryption and Decryption**:
  - Outgoing messages are encrypted using the server's public RSA key and signed with the client's private key.
  - Incoming messages are decrypted using the client's private RSA key and verified using the server's public key.

- **Real-Time Communication**:
  - Supports real-time message exchange using separate threads for reading and writing messages.

### Message Integrity

The system implements message integrity checking to ensure that messages have not been tampered with during transmission:

- **Digital Signatures**:
  - Before sending a message, the sender signs it with their private RSA key.
  - The signature is created by computing a SHA-256 hash of the message and encrypting the hash with the sender's private key.

- **Integrity Verification**:
  - When a message is received, the recipient verifies its integrity by:
    1. Decrypting the signature using the sender's public key
    2. Computing the hash of the received message
    3. Comparing the decrypted signature with the computed hash
  - If the values match, the message integrity is confirmed; otherwise, tampering is detected.

- **Clean RSA Implementation**:
  - The system uses RSA for both encryption and digital signatures.
  - No symmetric encryption or shared secrets are used, making this a "clean" RSA implementation.
  - Messages are broken into chunks to overcome RSA's size limitations for encrypting large messages.
  - Base64 encoding and JSON are used to handle the binary data and multiple chunks.

---

## Task Distribution

**Roman Prokhorov**:
- Implemented the RSA cryptosystem module, including key generation, encryption, and decryption.
- Wrote the server and client logic for a TCP-based chat system.
- Integrated encryption and decryption into the real-time chat system.

**Mykhailo Rykhalskyi**:
- Implemented message integrity verification using digital signatures.
- Enhanced the client-server communication protocol to support message integrity.
- Converted the hybrid encryption system to a clean RSA-only solution.

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