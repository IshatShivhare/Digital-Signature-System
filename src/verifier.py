"""
verifier.py
Complete workflow for verifying digital signatures on documents.
"""

import os
from crypto_core import CryptoCore
from metadata import MetadataManager
from utils import FileUtils, ValidationUtils, EncodingUtils


class SignatureVerifier:
    """Handles the complete signature verification workflow."""
    
    class VerificationResult:
        """Container for verification results."""
        
        def __init__(self):
            self.success = False
            self.message = ""
            self.details = {}
            self.warnings = []
        
        def __str__(self):
            status = "✓ VERIFIED" if self.success else "✗ VERIFICATION FAILED"
            output = [f"\n{status}", "=" * 50]
            output.append(self.message)
            
            if self.details:
                output.append("\nDetails:")
                for key, value in self.details.items():
                    output.append(f"  {key}: {value}")
            
            if self.warnings:
                output.append("\n⚠ Warnings:")
                for warning in self.warnings:
                    output.append(f"  - {warning}")
            
            return "\n".join(output)
    
    def __init__(self):
        """Initialize verifier."""
        pass
    
    def verify_document(self, document_path, signature_path, public_key_path, metadata_path=None):
        """
        Verify a document's digital signature.
        
        Args:
            document_path (str): Path to document to verify
            signature_path (str): Path to signature file
            public_key_path (str): Path to public key
            metadata_path (str): Optional path to metadata JSON
            
        Returns:
            VerificationResult: Complete verification results
        """
        result = self.VerificationResult()
        
        try:
            # Validate all file paths
            for path, name in [
                (document_path, "Document"),
                (signature_path, "Signature"),
                (public_key_path, "Public key")
            ]:
                is_valid, error = ValidationUtils.validate_file_path(path)
                if not is_valid:
                    result.message = f"{name} error: {error}"
                    return result
            
            # Load public key
            try:
                public_key = CryptoCore.load_public_key(public_key_path)
            except Exception as e:
                result.message = f"Failed to load public key: {str(e)}"
                return result
            
            # Load signature
            try:
                signature = FileUtils.read_binary(signature_path)
            except Exception as e:
                result.message = f"Failed to load signature: {str(e)}"
                return result
            
            # Hash the document
            try:
                hash_digest = CryptoCore.hash_file(document_path)
            except Exception as e:
                result.message = f"Failed to hash document: {str(e)}"
                return result
            
            # Verify signature
            is_valid = CryptoCore.verify_signature(public_key, hash_digest, signature)
            
            if not is_valid:
                result.message = "Signature verification FAILED. The document may have been modified or the signature is invalid."
                result.details = {
                    "Document": FileUtils.get_filename(document_path),
                    "Hash": EncodingUtils.bytes_to_hex(hash_digest)[:32] + "...",
                    "Status": "INVALID"
                }
                return result
            
            # Signature is valid
            result.success = True
            result.message = "Signature is VALID. The document is authentic and unmodified."
            
            # Calculate fingerprint
            fingerprint = CryptoCore.get_public_key_fingerprint(public_key)
            
            result.details = {
                "Document": FileUtils.get_filename(document_path),
                "Hash": EncodingUtils.bytes_to_hex(hash_digest)[:32] + "...",
                "Public Key Fingerprint": fingerprint[:32] + "...",
                "Status": "VERIFIED"
            }
            
            # Load and validate metadata if provided
            if metadata_path and FileUtils.file_exists(metadata_path):
                try:
                    metadata = MetadataManager.load_metadata(metadata_path)
                    
                    # Verify hash matches
                    metadata_hash = MetadataManager.extract_hash_from_metadata(metadata)
                    if metadata_hash != hash_digest:
                        result.warnings.append("Hash in metadata doesn't match document hash")
                    
                    # Verify signature matches
                    metadata_signature = MetadataManager.extract_signature_from_metadata(metadata)
                    if metadata_signature != signature:
                        result.warnings.append("Signature in metadata doesn't match signature file")
                    
                    # Verify fingerprint matches
                    if metadata.get('public_key_fingerprint') != fingerprint:
                        result.warnings.append("Public key fingerprint doesn't match metadata")
                    
                    # Validate metadata integrity
                    is_meta_valid, meta_warnings = MetadataManager.validate_metadata_integrity(
                        metadata,
                        FileUtils.get_filename(document_path)
                    )
                    result.warnings.extend(meta_warnings)
                    
                    # Add metadata details
                    result.details["Timestamp"] = MetadataManager.format_timestamp(
                        metadata.get('timestamp', 'N/A')
                    )
                    result.details["Algorithm"] = metadata.get('algorithm', 'N/A')
                    
                except Exception as e:
                    result.warnings.append(f"Failed to process metadata: {str(e)}")
            
            return result
            
        except Exception as e:
            result.message = f"Verification error: {str(e)}"
            return result
    
    def quick_verify(self, document_path, signature_path, public_key_path):
        """
        Quick verification without detailed reporting.
        
        Args:
            document_path (str): Path to document
            signature_path (str): Path to signature
            public_key_path (str): Path to public key
            
        Returns:
            bool: True if signature is valid
        """
        try:
            public_key = CryptoCore.load_public_key(public_key_path)
            signature = FileUtils.read_binary(signature_path)
            hash_digest = CryptoCore.hash_file(document_path)
            
            return CryptoCore.verify_signature(public_key, hash_digest, signature)
        except Exception:
            return False
    
    def verify_with_metadata_only(self, document_path, metadata_path, public_key_path):
        """
        Verify using metadata file (which contains the signature).
        
        Args:
            document_path (str): Path to document
            metadata_path (str): Path to metadata JSON
            public_key_path (str): Path to public key
            
        Returns:
            VerificationResult: Verification results
        """
        result = self.VerificationResult()
        
        try:
            # Load metadata
            metadata = MetadataManager.load_metadata(metadata_path)
            
            # Extract signature from metadata
            signature = MetadataManager.extract_signature_from_metadata(metadata)
            
            # Load public key
            public_key = CryptoCore.load_public_key(public_key_path)
            
            # Hash the document
            hash_digest = CryptoCore.hash_file(document_path)
            
            # Verify
            is_valid = CryptoCore.verify_signature(public_key, hash_digest, signature)
            
            if is_valid:
                result.success = True
                result.message = "Signature is VALID (verified using metadata)"
                result.details = {
                    "Document": FileUtils.get_filename(document_path),
                    "Timestamp": MetadataManager.format_timestamp(metadata['timestamp']),
                    "Algorithm": metadata['algorithm']
                }
            else:
                result.message = "Signature verification FAILED"
            
            return result
            
        except Exception as e:
            result.message = f"Verification error: {str(e)}"
            return result
    
    def batch_verify(self, verification_list):
        """
        Verify multiple documents at once.
        
        Args:
            verification_list (list): List of dicts with keys:
                - document_path
                - signature_path
                - public_key_path
                - metadata_path (optional)
        
        Returns:
            list: List of VerificationResult objects
        """
        results = []
        
        for item in verification_list:
            result = self.verify_document(
                item['document_path'],
                item['signature_path'],
                item['public_key_path'],
                item.get('metadata_path')
            )
            results.append(result)
        
        return results