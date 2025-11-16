"""
crypto_core.py
Core cryptographic operations: RSA key generation, signing, and verification.
Uses industry-standard cryptography library functions.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib


class CryptoCore:
    """Handles all cryptographic operations for the signature system."""
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """
        Generate RSA key pair.
        
        Args:
            key_size (int): RSA key size in bits (default: 2048)
            
        Returns:
            tuple: (private_key, public_key) objects
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def save_private_key(private_key, filepath, password=None):
        """
        Save private key to PEM file.
        
        Args:
            private_key: RSA private key object
            filepath (str): Path to save the key
            password (bytes): Optional password for encryption
        """
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    @staticmethod
    def save_public_key(public_key, filepath):
        """
        Save public key to PEM file.
        
        Args:
            public_key: RSA public key object
            filepath (str): Path to save the key
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    @staticmethod
    def load_private_key(filepath, password=None):
        """
        Load private key from PEM file.
        
        Args:
            filepath (str): Path to the key file
            password (bytes): Optional password for decryption
            
        Returns:
            RSA private key object
        """
        with open(filepath, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
        return private_key
    
    @staticmethod
    def load_public_key(filepath):
        """
        Load public key from PEM file.
        
        Args:
            filepath (str): Path to the key file
            
        Returns:
            RSA public key object
        """
        with open(filepath, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    
    @staticmethod
    def hash_file(filepath):
        """
        Compute SHA-256 hash of a file.
        
        Args:
            filepath (str): Path to the file
            
        Returns:
            bytes: SHA-256 hash digest
        """
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            # Read in chunks to handle large files
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        
        return sha256.digest()
    
    @staticmethod
    def sign_hash(private_key, hash_digest):
        """
        Sign a hash digest using RSA private key.
        
        Args:
            private_key: RSA private key object
            hash_digest (bytes): SHA-256 hash to sign
            
        Returns:
            bytes: Digital signature
        """
        signature = private_key.sign(
            hash_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(public_key, hash_digest, signature):
        """
        Verify a signature using RSA public key.
        
        Args:
            public_key: RSA public key object
            hash_digest (bytes): Original SHA-256 hash
            signature (bytes): Digital signature to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                hash_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_public_key_fingerprint(public_key):
        """
        Calculate SHA-256 fingerprint of public key.
        
        Args:
            public_key: RSA public key object
            
        Returns:
            str: Hex-encoded fingerprint
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(pem).hexdigest()
        return fingerprint