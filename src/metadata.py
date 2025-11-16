"""
metadata.py
Metadata creation, parsing, and validation for digital signatures.
"""

import json
from datetime import datetime
from utils import EncodingUtils, FileUtils


class MetadataManager:
    """Manages signature metadata including timestamps and file information."""
    
    ALGORITHM = "RSA-2048-SHA256"
    VERSION = "1.0"
    
    @staticmethod
    def create_metadata(file_path, hash_digest, signature, public_key_fingerprint):
        """
        Create metadata dictionary for a signed document.
        
        Args:
            file_path (str): Original file path
            hash_digest (bytes): SHA-256 hash of the document
            signature (bytes): Digital signature
            public_key_fingerprint (str): Fingerprint of public key used
            
        Returns:
            dict: Metadata dictionary
        """
        metadata = {
            "version": MetadataManager.VERSION,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "algorithm": MetadataManager.ALGORITHM,
            "file_name": FileUtils.get_filename(file_path),
            "file_size": FileUtils.get_file_size(file_path),
            "hash": EncodingUtils.bytes_to_base64(hash_digest),
            "signature": EncodingUtils.bytes_to_base64(signature),
            "public_key_fingerprint": public_key_fingerprint
        }
        return metadata
    
    @staticmethod
    def save_metadata(metadata, filepath):
        """
        Save metadata to JSON file.
        
        Args:
            metadata (dict): Metadata dictionary
            filepath (str): Path to save the JSON file
        """
        json_str = json.dumps(metadata, indent=2)
        FileUtils.write_text(filepath, json_str)
    
    @staticmethod
    def load_metadata(filepath):
        """
        Load metadata from JSON file.
        
        Args:
            filepath (str): Path to the JSON file
            
        Returns:
            dict: Metadata dictionary
            
        Raises:
            ValueError: If metadata is invalid
        """
        try:
            json_str = FileUtils.read_text(filepath)
            metadata = json.loads(json_str)
            
            # Validate required fields
            required_fields = [
                "timestamp", "algorithm", "file_name", 
                "hash", "signature", "public_key_fingerprint"
            ]
            
            for field in required_fields:
                if field not in metadata:
                    raise ValueError(f"Missing required field: {field}")
            
            return metadata
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to load metadata: {str(e)}")
    
    @staticmethod
    def extract_hash_from_metadata(metadata):
        """
        Extract and decode hash from metadata.
        
        Args:
            metadata (dict): Metadata dictionary
            
        Returns:
            bytes: Hash digest
        """
        return EncodingUtils.base64_to_bytes(metadata["hash"])
    
    @staticmethod
    def extract_signature_from_metadata(metadata):
        """
        Extract and decode signature from metadata.
        
        Args:
            metadata (dict): Metadata dictionary
            
        Returns:
            bytes: Signature
        """
        return EncodingUtils.base64_to_bytes(metadata["signature"])
    
    @staticmethod
    def format_timestamp(iso_timestamp):
        """
        Format ISO timestamp for display.
        
        Args:
            iso_timestamp (str): ISO 8601 timestamp
            
        Returns:
            str: Formatted timestamp
        """
        try:
            # Remove 'Z' suffix if present
            if iso_timestamp.endswith('Z'):
                iso_timestamp = iso_timestamp[:-1]
            
            dt = datetime.fromisoformat(iso_timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return iso_timestamp
    
    @staticmethod
    def validate_metadata_integrity(metadata, current_file_name=None):
        """
        Validate metadata integrity and consistency.
        
        Args:
            metadata (dict): Metadata dictionary
            current_file_name (str): Current file name to compare
            
        Returns:
            tuple: (bool, list) - (is_valid, warnings)
        """
        warnings = []
        
        # Check algorithm
        if metadata.get("algorithm") != MetadataManager.ALGORITHM:
            warnings.append(
                f"Algorithm mismatch: expected {MetadataManager.ALGORITHM}, "
                f"got {metadata.get('algorithm')}"
            )
        
        # Check file name if provided
        if current_file_name and metadata.get("file_name") != current_file_name:
            warnings.append(
                f"File name mismatch: metadata shows '{metadata.get('file_name')}', "
                f"current file is '{current_file_name}'"
            )
        
        # Check timestamp is in the past
        try:
            timestamp = metadata.get("timestamp", "").replace('Z', '')
            dt = datetime.fromisoformat(timestamp)
            if dt > datetime.utcnow():
                warnings.append("Timestamp is in the future")
        except Exception:
            warnings.append("Invalid timestamp format")
        
        is_valid = len(warnings) == 0
        return is_valid, warnings
    
    @staticmethod
    def get_metadata_summary(metadata):
        """
        Get human-readable summary of metadata.
        
        Args:
            metadata (dict): Metadata dictionary
            
        Returns:
            str: Formatted summary
        """
        summary = f"""
Signature Metadata:
==================
File Name: {metadata.get('file_name', 'N/A')}
File Size: {metadata.get('file_size', 'N/A')} bytes
Algorithm: {metadata.get('algorithm', 'N/A')}
Timestamp: {MetadataManager.format_timestamp(metadata.get('timestamp', 'N/A'))}
Public Key Fingerprint: {metadata.get('public_key_fingerprint', 'N/A')[:16]}...
"""
        return summary.strip()