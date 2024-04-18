import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_ecdh_key():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_symmetric_key(shared_secret):
    salt = os.urandom(16)
    info = b"AES symmetric key"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv + ct

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pt

def main():
    print("===== Secure Communication using ECDH and AES =====")
    alice_private_key, alice_public_key = generate_ecdh_key()
    bob_private_key, bob_public_key = generate_ecdh_key()

    # Key exchange
    alice_shared_secret = derive_shared_secret(alice_private_key, bob_public_key)
    bob_shared_secret = derive_shared_secret(bob_private_key, alice_public_key)

    # Derive symmetric keys
    alice_symmetric_key = derive_symmetric_key(alice_shared_secret)
    bob_symmetric_key = derive_symmetric_key(bob_shared_secret)

    # Alice sends a message to Bob
    message_from_alice = b"Hello Bob! This is a secret message."
    print("\nMessage from Alice:", message_from_alice.decode())

    # Encryption by Alice
    encrypted_message = encrypt_message(message_from_alice, alice_symmetric_key)

    # Decryption by Bob
    decrypted_message = decrypt_message(encrypted_message, bob_symmetric_key)
    print("Decrypted Message by Bob:", decrypted_message.decode())

if __name__ == "__main__":
    main()
