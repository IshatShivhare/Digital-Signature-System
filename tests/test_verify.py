"""
test_verify.py
Unit tests for signature verification functionality.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import unittest
import tempfile
import shutil
from signer import DocumentSigner
from verifier import SignatureVerifier
from utils import FileUtils


class TestSignatureVerification(unittest.TestCase):
    """Test cases for signature verification."""
    
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
        
        # Initialize signer and verifier
        self.signer = DocumentSigner(self.keys_dir, self.signatures_dir)
        self.verifier = SignatureVerifier()
        
        # Sign the test document
        self.sign_result = self.signer.sign_document(self.test_doc_path, generate_qr=False)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_valid_signature_verification(self):
        """Test verification of valid signature."""
        result = self.verifier.verify_document(
            self.test_doc_path,
            self.sign_result['signature'],
            self.sign_result['public_key'],
            self.sign_result['metadata']
        )
        
        self.assertTrue(result.success)
        self.assertIn("VALID", result.message)
    
    def test_tampered_document_detection(self):
        """Test that tampering with document is detected."""
        # Modify the document
        tampered_path = os.path.join(self.test_dir, 'tampered.txt')
        with open(tampered_path, 'w') as f:
            f.write("This document has been tampered with!")
        
        # Try to verify with original signature
        result = self.verifier.verify_document(
            tampered_path,
            self.sign_result['signature'],
            self.sign_result['public_key']
        )
        
        self.assertFalse(result.success)
        self.assertIn("FAILED", result.message)
    
    def test_wrong_public_key(self):
        """Test verification fails with wrong public key."""
        # Generate different keys
        other_signer = DocumentSigner(
            os.path.join(self.test_dir, 'other_keys'),
            os.path.join(self.test_dir, 'other_sigs')
        )
        other_signer.generate_keys()
        
        # Try to verify with wrong key
        result = self.verifier.verify_document(
            self.test_doc_path,
            self.sign_result['signature'],
            other_signer.public_key_path
        )
        
        self.assertFalse(result.success)
    
    def test_corrupted_signature(self):
        """Test detection of corrupted signature."""
        # Create corrupted signature
        corrupted_sig_path = os.path.join(self.test_dir, 'corrupted.sig')
        
        # Read original signature and corrupt it
        original_sig = FileUtils.read_binary(self.sign_result['signature'])
        corrupted_sig = bytes([b ^ 0xFF for b in original_sig[:10]]) + original_sig[10:]
        FileUtils.write_binary(corrupted_sig_path, corrupted_sig)
        
        # Try to verify
        result = self.verifier.verify_document(
            self.test_doc_path,
            corrupted_sig_path,
            self.sign_result['public_key']
        )
        
        self.assertFalse(result.success)
    
    def test_quick_verify(self):
        """Test quick verification without detailed output."""
        is_valid = self.verifier.quick_verify(
            self.test_doc_path,
            self.sign_result['signature'],
            self.sign_result['public_key']
        )
        
        self.assertTrue(is_valid)
    
    def test_quick_verify_tampered(self):
        """Test quick verification detects tampering."""
        # Tamper with document
        with open(self.test_doc_path, 'a') as f:
            f.write(" TAMPERED")
        
        is_valid = self.verifier.quick_verify(
            self.test_doc_path,
            self.sign_result['signature'],
            self.sign_result['public_key']
        )
        
        self.assertFalse(is_valid)
    
    def test_verify_with_metadata_only(self):
        """Test verification using metadata file."""
        result = self.verifier.verify_with_metadata_only(
            self.test_doc_path,
            self.sign_result['metadata'],
            self.sign_result['public_key']
        )
        
        self.assertTrue(result.success)
    
    def test_missing_document_error(self):
        """Test verification fails gracefully with missing document."""
        result = self.verifier.verify_document(
            '/nonexistent/file.txt',
            self.sign_result['signature'],
            self.sign_result['public_key']
        )
        
        self.assertFalse(result.success)
        self.assertIn("error", result.message.lower())
    
    def test_missing_signature_error(self):
        """Test verification fails gracefully with missing signature."""
        result = self.verifier.verify_document(
            self.test_doc_path,
            '/nonexistent/signature.sig',
            self.sign_result['public_key']
        )
        
        self.assertFalse(result.success)
    
    def test_missing_public_key_error(self):
        """Test verification fails gracefully with missing public key."""
        result = self.verifier.verify_document(
            self.test_doc_path,
            self.sign_result['signature'],
            '/nonexistent/key.pem'
        )
        
        self.assertFalse(result.success)
    
    def test_metadata_warnings(self):
        """Test that metadata inconsistencies generate warnings."""
        # Rename the document
        renamed_path = os.path.join(self.test_dir, 'renamed_document.txt')
        shutil.copy(self.test_doc_path, renamed_path)
        
        # Verify with original metadata
        result = self.verifier.verify_document(
            renamed_path,
            self.sign_result['signature'],
            self.sign_result['public_key'],
            self.sign_result['metadata']
        )
        
        # Should still verify but with warnings
        self.assertTrue(result.success)
        self.assertTrue(len(result.warnings) > 0)
    
    def test_batch_verification(self):
        """Test batch verification of multiple documents."""
        # Create and sign multiple documents
        docs = []
        for i in range(3):
            doc_path = os.path.join(self.test_dir, f'doc_{i}.txt')
            with open(doc_path, 'w') as f:
                f.write(f"Document {i}")
            
            result = self.signer.sign_document(doc_path, generate_qr=False)
            docs.append({
                'document_path': doc_path,
                'signature_path': result['signature'],
                'public_key_path': result['public_key'],
                'metadata_path': result['metadata']
            })
        
        # Batch verify
        results = self.verifier.batch_verify(docs)
        
        # All should be valid
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertTrue(result.success)
    
    def test_verification_result_string_format(self):
        """Test that VerificationResult formats correctly as string."""
        result = self.verifier.verify_document(
            self.test_doc_path,
            self.sign_result['signature'],
            self.sign_result['public_key'],
            self.sign_result['metadata']
        )
        
        result_str = str(result)
        
        # Check for expected content
        self.assertIn("VERIFIED", result_str)
        self.assertIn("Details:", result_str)
    
    def test_empty_file_verification(self):
        """Test verification of empty file."""
        # Create empty file
        empty_file = os.path.join(self.test_dir, 'empty.txt')
        open(empty_file, 'w').close()
        
        # Sign it
        result = self.signer.sign_document(empty_file, generate_qr=False)
        
        # Verify it
        verify_result = self.verifier.verify_document(
            empty_file,
            result['signature'],
            result['public_key']
        )
        
        self.assertTrue(verify_result.success)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.verifier = SignatureVerifier()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_binary_file_verification(self):
        """Test signing and verifying binary files."""
        # Create binary file
        binary_file = os.path.join(self.test_dir, 'binary.dat')
        with open(binary_file, 'wb') as f:
            f.write(os.urandom(1024))
        
        # Sign and verify
        signer = DocumentSigner(
            os.path.join(self.test_dir, 'keys'),
            os.path.join(self.test_dir, 'sigs')
        )
        
        result = signer.sign_document(binary_file, generate_qr=False)
        verify_result = self.verifier.verify_document(
            binary_file,
            result['signature'],
            result['public_key']
        )
        
        self.assertTrue(verify_result.success)
    
    def test_special_characters_in_filename(self):
        """Test handling files with special characters."""
        # Create file with special chars
        special_file = os.path.join(self.test_dir, 'test file (1) [copy].txt')
        with open(special_file, 'w') as f:
            f.write("Test content")
        
        signer = DocumentSigner(
            os.path.join(self.test_dir, 'keys'),
            os.path.join(self.test_dir, 'sigs')
        )
        
        result = signer.sign_document(special_file, generate_qr=False)
        verify_result = self.verifier.verify_document(
            special_file,
            result['signature'],
            result['public_key']
        )
        
        self.assertTrue(verify_result.success)


if __name__ == '__main__':
    unittest.main()