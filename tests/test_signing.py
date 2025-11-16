"""
test_signing.py
Unit tests for document signing functionality.
"""

import unittest
import os
import tempfile
import shutil
from signer import DocumentSigner
from crypto_core import CryptoCore
from utils import FileUtils


class TestDocumentSigning(unittest.TestCase):
    """Test cases for document signing."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directories
        self.test_dir = tempfile.mkdtemp()
        self.keys_dir = os.path.join(self.test_dir, 'keys')
        self.signatures_dir = os.path.join(self.test_dir, 'signatures')
        
        # Create test document
        self.test_doc_path = os.path.join(self.test_dir, 'test_document.txt')
        with open(self.test_doc_path, 'w') as f:
            f.write("This is a test document for digital signature verification.")
        
        # Initialize signer
        self.signer = DocumentSigner(self.keys_dir, self.signatures_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_key_generation(self):
        """Test RSA key pair generation."""
        private_key_path, public_key_path = self.signer.generate_keys()
        
        # Verify keys exist
        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))
        
        # Verify keys can be loaded
        private_key = CryptoCore.load_private_key(private_key_path)
        public_key = CryptoCore.load_public_key(public_key_path)
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
    
    def test_document_signing(self):
        """Test signing a document."""
        result = self.signer.sign_document(self.test_doc_path, generate_qr=False)
        
        # Verify all required outputs exist
        self.assertTrue(os.path.exists(result['signature']))
        self.assertTrue(os.path.exists(result['metadata']))
        self.assertTrue(os.path.exists(result['public_key']))
        self.assertTrue(os.path.exists(result['private_key']))
        
        # Verify fingerprint is generated
        self.assertIsNotNone(result['fingerprint'])
        self.assertTrue(len(result['fingerprint']) > 0)
    
    def test_signing_with_qr_codes(self):
        """Test signing with QR code generation."""
        result = self.signer.sign_document(self.test_doc_path, generate_qr=True)
        
        # Verify QR codes are generated
        self.assertIn('qr_codes', result)
        self.assertIn('public_key', result['qr_codes'])
        self.assertIn('fingerprint', result['qr_codes'])
        self.assertIn('signature_info', result['qr_codes'])
        
        # Verify QR code files exist
        for qr_path in result['qr_codes'].values():
            self.assertTrue(os.path.exists(qr_path))
    
    def test_signing_nonexistent_file(self):
        """Test signing a nonexistent file raises error."""
        with self.assertRaises(ValueError):
            self.signer.sign_document('/nonexistent/file.txt')
    
    def test_signature_file_format(self):
        """Test signature file is in correct binary format."""
        result = self.signer.sign_document(self.test_doc_path, generate_qr=False)
        
        # Read signature file
        signature_data = FileUtils.read_binary(result['signature'])
        
        # Verify it's binary data
        self.assertIsInstance(signature_data, bytes)
        self.assertTrue(len(signature_data) > 0)
    
    def test_metadata_structure(self):
        """Test metadata contains all required fields."""
        result = self.signer.sign_document(self.test_doc_path, generate_qr=False)
        
        from metadata import MetadataManager
        metadata = MetadataManager.load_metadata(result['metadata'])
        
        # Check required fields
        required_fields = [
            'timestamp', 'algorithm', 'file_name', 
            'hash', 'signature', 'public_key_fingerprint'
        ]
        
        for field in required_fields:
            self.assertIn(field, metadata)
            self.assertIsNotNone(metadata[field])
    
    def test_ensure_keys_exist(self):
        """Test automatic key generation if keys don't exist."""
        # Initially no keys
        self.assertFalse(os.path.exists(self.signer.private_key_path))
        
        # Call ensure_keys_exist
        private_key, public_key = self.signer.ensure_keys_exist()
        
        # Keys should now exist
        self.assertTrue(os.path.exists(private_key))
        self.assertTrue(os.path.exists(public_key))
    
    def test_signing_large_file(self):
        """Test signing a larger file."""
        # Create a 1MB file
        large_file = os.path.join(self.test_dir, 'large_file.bin')
        with open(large_file, 'wb') as f:
            f.write(os.urandom(1024 * 1024))
        
        result = self.signer.sign_document(large_file, generate_qr=False)
        
        # Verify signature was created
        self.assertTrue(os.path.exists(result['signature']))
    
    def test_multiple_signatures(self):
        """Test signing multiple documents."""
        # Create multiple test files
        files = []
        for i in range(3):
            file_path = os.path.join(self.test_dir, f'doc_{i}.txt')
            with open(file_path, 'w') as f:
                f.write(f"Test document {i}")
            files.append(file_path)
        
        # Sign all files
        results = []
        for file_path in files:
            result = self.signer.sign_document(file_path, generate_qr=False)
            results.append(result)
        
        # Verify all signatures exist
        for result in results:
            self.assertTrue(os.path.exists(result['signature']))
            self.assertTrue(os.path.exists(result['metadata']))


class TestCryptographicOperations(unittest.TestCase):
    """Test core cryptographic operations."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_hash_consistency(self):
        """Test that hashing the same file produces same hash."""
        # Create test file
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        # Hash twice
        hash1 = CryptoCore.hash_file(test_file)
        hash2 = CryptoCore.hash_file(test_file)
        
        # Should be identical
        self.assertEqual(hash1, hash2)
    
    def test_hash_changes_with_content(self):
        """Test that changing file content changes hash."""
        test_file = os.path.join(self.test_dir, 'test.txt')
        
        # Create and hash original
        with open(test_file, 'w') as f:
            f.write("Original content")
        hash1 = CryptoCore.hash_file(test_file)
        
        # Modify and hash again
        with open(test_file, 'w') as f:
            f.write("Modified content")
        hash2 = CryptoCore.hash_file(test_file)
        
        # Hashes should be different
        self.assertNotEqual(hash1, hash2)
    
    def test_signature_verification_with_matching_keys(self):
        """Test that signature verifies with correct keys."""
        # Generate keys
        private_key, public_key = CryptoCore.generate_rsa_keypair()
        
        # Create test data
        test_data = b"Test message for signing"
        hash_digest = CryptoCore.hash_file.__wrapped__(test_data)
        
        # Sign
        signature = CryptoCore.sign_hash(private_key, test_data)
        
        # Verify
        is_valid = CryptoCore.verify_signature(public_key, test_data, signature)
        
        self.assertTrue(is_valid)
    
    def test_public_key_fingerprint(self):
        """Test public key fingerprint generation."""
        private_key, public_key = CryptoCore.generate_rsa_keypair()
        
        fingerprint1 = CryptoCore.get_public_key_fingerprint(public_key)
        fingerprint2 = CryptoCore.get_public_key_fingerprint(public_key)
        
        # Should be consistent
        self.assertEqual(fingerprint1, fingerprint2)
        
        # Should be hex string
        self.assertTrue(all(c in '0123456789abcdef' for c in fingerprint1))


if __name__ == '__main__':
    unittest.main()