"""
signer.py
Complete workflow for signing documents with RSA digital signatures.
"""

import os
from crypto_core import CryptoCore
from metadata import MetadataManager
from qr_module import QRCodeGenerator
from utils import FileUtils, ValidationUtils


class DocumentSigner:
    """Handles the complete document signing workflow."""
    
    def __init__(self, keys_dir='keys', signatures_dir='signatures'):
        """
        Initialize signer with directory paths.
        
        Args:
            keys_dir (str): Directory to store keys
            signatures_dir (str): Directory to store signatures
        """
        self.keys_dir = keys_dir
        self.signatures_dir = signatures_dir
        
        # Ensure directories exist
        FileUtils.ensure_directory(keys_dir)
        FileUtils.ensure_directory(signatures_dir)
        
        self.private_key_path = os.path.join(keys_dir, 'private_key.pem')
        self.public_key_path = os.path.join(keys_dir, 'public_key.pem')
    
    def generate_keys(self, force=False):
        """
        Generate new RSA key pair.
        
        Args:
            force (bool): If True, overwrite existing keys
            
        Returns:
            tuple: (private_key_path, public_key_path)
            
        Raises:
            FileExistsError: If keys exist and force=False
        """
        if not force and (FileUtils.file_exists(self.private_key_path) or 
                          FileUtils.file_exists(self.public_key_path)):
            raise FileExistsError("Keys already exist. Use force=True to overwrite.")
        
        # Generate key pair
        private_key, public_key = CryptoCore.generate_rsa_keypair(key_size=2048)
        
        # Save keys
        CryptoCore.save_private_key(private_key, self.private_key_path)
        CryptoCore.save_public_key(public_key, self.public_key_path)
        
        return self.private_key_path, self.public_key_path
    
    def ensure_keys_exist(self):
        """
        Check if keys exist, generate if not.
        
        Returns:
            tuple: (private_key_path, public_key_path)
        """
        if not (FileUtils.file_exists(self.private_key_path) and 
                FileUtils.file_exists(self.public_key_path)):
            return self.generate_keys()
        
        return self.private_key_path, self.public_key_path
    
    def sign_document(self, document_path, generate_qr=True):
        """
        Sign a document and generate all associated files.
        
        Args:
            document_path (str): Path to document to sign
            generate_qr (bool): Whether to generate QR codes
            
        Returns:
            dict: Paths to all generated files
            
        Raises:
            ValueError: If document path is invalid
            FileNotFoundError: If keys don't exist
        """
        # Validate document
        is_valid, error = ValidationUtils.validate_file_path(document_path)
        if not is_valid:
            raise ValueError(error)
        
        # Ensure keys exist
        self.ensure_keys_exist()
        
        # Load keys
        private_key = CryptoCore.load_private_key(self.private_key_path)
        public_key = CryptoCore.load_public_key(self.public_key_path)
        
        # Hash the document
        hash_digest = CryptoCore.hash_file(document_path)
        
        # Sign the hash
        signature = CryptoCore.sign_hash(private_key, hash_digest)
        
        # Get public key fingerprint
        fingerprint = CryptoCore.get_public_key_fingerprint(public_key)
        
        # Create metadata
        metadata = MetadataManager.create_metadata(
            document_path,
            hash_digest,
            signature,
            fingerprint
        )
        
        # Generate output filenames
        doc_basename = os.path.splitext(FileUtils.get_filename(document_path))[0]
        sig_path = os.path.join(self.signatures_dir, f"{doc_basename}.sig")
        metadata_path = os.path.join(self.signatures_dir, f"{doc_basename}_metadata.json")
        
        # Save signature file
        FileUtils.write_binary(sig_path, signature)
        
        # Save metadata
        MetadataManager.save_metadata(metadata, metadata_path)
        
        result = {
            'document': document_path,
            'signature': sig_path,
            'metadata': metadata_path,
            'public_key': self.public_key_path,
            'private_key': self.private_key_path,
            'fingerprint': fingerprint
        }
        
        # Generate QR codes if requested
        if generate_qr:
            qr_dir = os.path.join(self.signatures_dir, f"{doc_basename}_qr")
            qr_paths = QRCodeGenerator.create_qr_grid(
                self.public_key_path,
                fingerprint,
                metadata,
                qr_dir
            )
            result['qr_codes'] = qr_paths
        
        return result
    
    def get_signing_info(self):
        """
        Get information about current signing configuration.
        
        Returns:
            dict: Configuration information
        """
        keys_exist = (FileUtils.file_exists(self.private_key_path) and 
                      FileUtils.file_exists(self.public_key_path))
        
        info = {
            'keys_directory': self.keys_dir,
            'signatures_directory': self.signatures_dir,
            'private_key_path': self.private_key_path,
            'public_key_path': self.public_key_path,
            'keys_exist': keys_exist
        }
        
        if keys_exist:
            try:
                public_key = CryptoCore.load_public_key(self.public_key_path)
                info['public_key_fingerprint'] = CryptoCore.get_public_key_fingerprint(public_key)
            except Exception as e:
                info['error'] = f"Failed to load keys: {str(e)}"
        
        return info
    
    def export_public_key(self, output_path):
        """
        Copy public key to a specified location.
        
        Args:
            output_path (str): Destination path for public key
            
        Returns:
            str: Path to exported key
        """
        if not FileUtils.file_exists(self.public_key_path):
            raise FileNotFoundError("Public key not found. Generate keys first.")
        
        public_key_data = FileUtils.read_binary(self.public_key_path)
        FileUtils.write_binary(output_path, public_key_data)
        
        return output_path