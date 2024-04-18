import random
import sympy

# Function to check if a number is an Armstrong number
def is_armstrong_number(num):
    num_str = str(num)
    num_digits = len(num_str)
    armstrong_sum = sum(int(digit)**num_digits for digit in num_str)
    return armstrong_sum == num

# Function to generate a private key (Armstrong number)
def generate_private_key():
    while True:
        num = random.randint(1000, 1000000)  # Adjust range as needed
        if is_armstrong_number(num):
            return num

# Function to generate a large prime number
def generate_large_prime():
    return sympy.randprime(10**50, 10**100)  # Generate a random prime between 10^50 and 10^100

# Function to generate a public key
def generate_public_key(private_key, generator, prime):
    return pow(generator, private_key, prime)

# Function to calculate the shared secret key
def calculate_secret_key(private_key, received_public_key, prime):
    return pow(received_public_key, private_key, prime)

# Main function to simulate communication between Alice and Bob
def simulate_communication():
    print("===== Simulation of Communication between Alice and Bob =====")

    # Generate large prime number (could be pre-defined)
    prime = generate_large_prime()

    # Choose a generator value (could be pre-defined)
    generator = 2

    # Alice's side
    alice_private_key = generate_private_key()
    alice_public_key = generate_public_key(alice_private_key, generator, prime)
    print("Alice's Private Key:", alice_private_key)
    print("Alice's Public Key:", alice_public_key)

    # Bob's side
    bob_private_key = generate_private_key()
    bob_public_key = generate_public_key(bob_private_key, generator, prime)
    print("Bob's Private Key:", bob_private_key)
    print("Bob's Public Key:", bob_public_key)

    # Key exchange
    alice_secret_key = calculate_secret_key(alice_private_key, bob_public_key, prime)
    bob_secret_key = calculate_secret_key(bob_private_key, alice_public_key, prime)

    # Verify shared secret key
    assert alice_secret_key == bob_secret_key
    print("Shared Secret Key:", alice_secret_key)

    # Alice sends a message to Bob
    message_from_alice = "Hello Bob! This is a secret message."
    print("\nMessage from Alice:", message_from_alice)

    # Encryption by Alice
    encrypted_message = encrypt_message(message_from_alice, alice_secret_key)
    print("Encrypted Message:", encrypted_message)

    # Decryption by Bob
    decrypted_message = decrypt_message(encrypted_message, bob_secret_key)
    print("Decrypted Message by Bob:", decrypted_message)

def encrypt_message(message, key):
    # Simple encryption function (for demonstration purposes only)
    encrypted_message = ""
    for char in message:
        encrypted_char = chr(ord(char) + key)  # Shift character by the key
        encrypted_message += encrypted_char
    return encrypted_message

def decrypt_message(encrypted_message, key):
    # Simple decryption function (for demonstration purposes only)
    decrypted_message = ""
    for char in encrypted_message:
        decrypted_char = chr(ord(char) - key)  # Shift character back by the key
        decrypted_message += decrypted_char
    return decrypted_message

# Run the simulation
simulate_communication()
