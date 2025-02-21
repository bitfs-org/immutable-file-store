import unittest
import secrets
from bsv import PrivateKey
from secure_channel import SecureChannel

class TestSecureChannel(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        # Create private keys for Alice and Bob
        self.alice_private_key = PrivateKey(secrets.token_bytes(32))
        self.bob_private_key = PrivateKey(secrets.token_bytes(32))
        
        # Create secure channels for both parties
        self.alice_channel = SecureChannel(self.alice_private_key)
        self.bob_channel = SecureChannel(self.bob_private_key)

    def test_shared_secret_generation(self):
        """Test that both parties generate the same shared secret"""
        # Get public keys
        alice_public_key = self.alice_channel.get_public_key()
        bob_public_key = self.bob_channel.get_public_key()
        
        # Generate shared secrets
        alice_shared_secret = self.alice_channel.generate_shared_secret(bob_public_key)
        bob_shared_secret = self.bob_channel.generate_shared_secret(alice_public_key)
        
        # Verify shared secrets match
        self.assertEqual(alice_shared_secret, bob_shared_secret)

    def test_message_encryption_decryption(self):
        """Test encrypting and decrypting messages between parties"""
        # Get public keys
        alice_public_key = self.alice_channel.get_public_key()
        bob_public_key = self.bob_channel.get_public_key()
        
        # Test message
        message = b"Hello, Bob! This is a secret message."
        
        # Alice encrypts message for Bob
        encrypted_message = self.alice_channel.encrypt_for_peer(message, bob_public_key)
        
        # Bob decrypts message from Alice
        decrypted_message = self.bob_channel.decrypt_from_peer(encrypted_message, alice_public_key)
        
        # Verify decrypted message matches original
        self.assertEqual(message, decrypted_message)

    def test_bidirectional_communication(self):
        """Test both parties can send and receive messages"""
        # Get public keys
        alice_public_key = self.alice_channel.get_public_key()
        bob_public_key = self.bob_channel.get_public_key()
        
        # Alice to Bob
        message_to_bob = b"Hello Bob!"
        encrypted_for_bob = self.alice_channel.encrypt_for_peer(message_to_bob, bob_public_key)
        decrypted_by_bob = self.bob_channel.decrypt_from_peer(encrypted_for_bob, alice_public_key)
        self.assertEqual(message_to_bob, decrypted_by_bob)
        
        # Bob to Alice
        message_to_alice = b"Hi Alice!"
        encrypted_for_alice = self.bob_channel.encrypt_for_peer(message_to_alice, alice_public_key)
        decrypted_by_alice = self.alice_channel.decrypt_from_peer(encrypted_for_alice, bob_public_key)
        self.assertEqual(message_to_alice, decrypted_by_alice)

    def test_long_message(self):
        """Test encrypting and decrypting a long message"""
        # Get public keys
        alice_public_key = self.alice_channel.get_public_key()
        bob_public_key = self.bob_channel.get_public_key()
        
        # Generate a long random message
        long_message = secrets.token_bytes(1024)
        
        # Alice encrypts for Bob
        encrypted_message = self.alice_channel.encrypt_for_peer(long_message, bob_public_key)
        
        # Bob decrypts from Alice
        decrypted_message = self.bob_channel.decrypt_from_peer(encrypted_message, alice_public_key)
        
        # Verify decrypted message matches original
        self.assertEqual(long_message, decrypted_message)

if __name__ == '__main__':
    unittest.main() 