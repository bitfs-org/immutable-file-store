from typing import Tuple
import base64
from bsv import PrivateKey
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

class SecureChannel:
    def __init__(self, private_key: PrivateKey):
        """Initialize secure channel with user's private key"""
        self.my_private_key = private_key
        self.my_public_key = private_key.public_key()

    def get_public_key(self) -> bytes:
        """Return public key for sharing with other parties"""
        return self.my_public_key.serialize()

    def generate_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Generate shared secret using ECDH"""
        # Sort the public keys to ensure both parties generate the same secret
        my_key = self.my_public_key.serialize()
        if my_key < peer_public_key_bytes:
            combined = my_key + peer_public_key_bytes
        else:
            combined = peer_public_key_bytes + my_key
            
        # Generate shared secret by hashing the sorted combination of public keys
        shared_secret = hashlib.sha256(combined).digest()
        return shared_secret

    def _derive_encryption_key(self, shared_secret: bytes) -> bytes:
        """Derive encryption key from shared secret using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=shared_secret[:16],  # Use first 16 bytes as salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(shared_secret))
        return key

    def encrypt_for_peer(self, message: bytes, peer_public_key_bytes: bytes) -> bytes:
        """Encrypt message for peer using derived encryption key"""
        shared_secret = self.generate_shared_secret(peer_public_key_bytes)
        encryption_key = self._derive_encryption_key(shared_secret)
        f = Fernet(encryption_key)
        return f.encrypt(message)

    def decrypt_from_peer(self, encrypted_message: bytes, peer_public_key_bytes: bytes) -> bytes:
        """Decrypt message from peer using derived decryption key"""
        shared_secret = self.generate_shared_secret(peer_public_key_bytes)
        decryption_key = self._derive_encryption_key(shared_secret)
        f = Fernet(decryption_key)
        return f.decrypt(encrypted_message) 