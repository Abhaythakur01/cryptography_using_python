import os

def generate_one_time_pad(length):
    return os.urandom(length)

def encrypt(message, key):
    return bytes([m ^ k for m, k in zip(message, key)])

def decrypt(ciphertext, key):
    return bytes([c ^ k for c, k in zip(ciphertext, key)])

def main():
    message = b"Hello, world!"
    key = generate_one_time_pad(len(message))

    # Encryption
    ciphertext = encrypt(message, key)
    print("Ciphertext:", ciphertext)

    # Decryption
    decrypted_message = decrypt(ciphertext, key)
    print("Decrypted Message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
