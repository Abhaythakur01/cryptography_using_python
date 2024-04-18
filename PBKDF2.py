from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Key generation using PBKDF2
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Encryption using AES-GCM
def encrypt_message(plaintext, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(b"associated_data")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

# Decryption using AES-GCM
def decrypt_message(iv, ciphertext, tag, key):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(b"associated_data")
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    # Password-based key generation
    password = b"my_secure_password"
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # Plaintext message
    plaintext = b"Hello, world!"

    # Encryption
    iv, ciphertext, tag = encrypt_message(plaintext, key)

    # Decryption
    decrypted_plaintext = decrypt_message(iv, ciphertext, tag, key)

    print("Original Plaintext:", plaintext.decode())
    print("Decrypted Plaintext:", decrypted_plaintext.decode())

if __name__ == "__main__":
    main()
