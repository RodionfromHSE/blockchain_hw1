import unittest
from rsa import generate_keypair, encrypt, decrypt

class TestRSA(unittest.TestCase):
    def setUp(self):
        # Generate a key pair with a small bit length for testing
        self.public_key, self.private_key = generate_keypair(bits=128)

    def test_encryption_decryption(self):
        message = "Test RSA encryption"
        cipher = encrypt(self.public_key, message)
        decrypted_message = decrypt(self.private_key, cipher)
        self.assertEqual(message, decrypted_message)

    def test_empty_message(self):
        message = ""
        cipher = encrypt(self.public_key, message)
        decrypted_message = decrypt(self.private_key, cipher)
        self.assertEqual(message, decrypted_message)

    def test_non_ascii_message(self):
        message = "Привет, мир!"  # "Hello, world!" in Russian
        cipher = encrypt(self.public_key, message)
        decrypted_message = decrypt(self.private_key, cipher)
        self.assertEqual(message, decrypted_message)

if __name__ == '__main__':
    unittest.main()
