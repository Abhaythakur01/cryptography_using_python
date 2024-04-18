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

# Main function to demonstrate key exchange
def main():
    # Generate large prime number (could be pre-defined)
    prime = generate_large_prime()

    # Choose a generator value (could be pre-defined)
    generator = 2

    # Alice's side
    alice_private_key = generate_private_key()
    alice_public_key = generate_public_key(alice_private_key, generator, prime)
    
    # Bob's side
    bob_private_key = generate_private_key()
    bob_public_key = generate_public_key(bob_private_key, generator, prime)

    # Key exchange
    alice_secret_key = calculate_secret_key(alice_private_key, bob_public_key, prime)
    bob_secret_key = calculate_secret_key(bob_private_key, alice_public_key, prime)

    # Verify shared secret key
    assert alice_secret_key == bob_secret_key
    print("Shared secret key:", alice_secret_key)

if __name__ == "__main__":
    main()
