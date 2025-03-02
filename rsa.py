import random
from math import gcd as math_gcd

def is_prime(n, k=5):
    """Miller-Rabin primality test.
    
    Args:
        n (int): The number to test.
        k (int): Number of testing rounds.
    
    Returns:
        bool: True if n is probably prime, False otherwise.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^s * d with d odd.
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(bits):
    """Generate an odd integer with the specified number of bits."""
    candidate = random.getrandbits(bits)
    candidate |= (1 << (bits - 1)) | 1
    return candidate

def generate_prime_number(bits):
    """Generate a prime number of the specified bit length."""
    candidate = generate_prime_candidate(bits)
    while not is_prime(candidate):
        candidate = generate_prime_candidate(bits)
    return candidate

def modinv(a, m):
    """Compute the modular inverse of a modulo m using the Extended Euclidean Algorithm."""
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair(bits=16):
    """
    Generate RSA public and private keys.
    
    Args:
        bits (int): Bit length for prime numbers.
    
    Returns:
        tuple: (public_key, private_key)
               public_key is a tuple (e, n)
               private_key is a tuple (d, n)
    """
    p = generate_prime_number(bits)
    q = generate_prime_number(bits)
    # Ensure p and q are distinct.
    while q == p:
        q = generate_prime_number(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e (commonly 65537) and ensure it is coprime with phi.
    e = 65537
    if math_gcd(e, phi) != 1:
        e = random.randrange(2, phi)
        while math_gcd(e, phi) != 1:
            e = random.randrange(2, phi)

    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    """
    Encrypt the plaintext with the public key.
    
    Args:
        pk (tuple): The public key (e, n)
        plaintext (str): The message to encrypt.
        
    Returns:
        int: The encrypted message as an integer.
        
    Raises:
        ValueError: If the plaintext integer is not smaller than n.
    """
    key, n = pk
    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_int = int.from_bytes(plaintext_bytes, byteorder='big')
    
    if plaintext_int >= n:
        raise ValueError("The plaintext is too long for the key size.")
    
    cipher_int = pow(plaintext_int, key, n)
    return cipher_int

def decrypt(pk, ciphertext):
    """
    Decrypt the ciphertext with the private key.
    
    Args:
        pk (tuple): The private key (d, n)
        ciphertext (int): The encrypted message.
        
    Returns:
        str: The decrypted plaintext.
    """
    key, n = pk
    plaintext_int = pow(ciphertext, key, n)
    num_bytes = (plaintext_int.bit_length() + 7) // 8
    plaintext_bytes = plaintext_int.to_bytes(num_bytes, byteorder='big')
    return plaintext_bytes.decode('utf-8')
