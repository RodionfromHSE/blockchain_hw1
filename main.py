from rsa import generate_keypair, encrypt, decrypt

def main():
    print("RSA Algorithm Demonstration")
    public_key, private_key = generate_keypair(bits=64)
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    
    message = "Hello RSA!"
    print("\nOriginal Message:", message)
    
    # Encrypt the message
    cipher = encrypt(public_key, message)
    print("Encrypted Message:", cipher)
    
    # Decrypt the message
    decrypted_message = decrypt(private_key, cipher)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
