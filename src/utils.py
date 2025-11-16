"""
utils.py
Utility functions for file handling, encoding, and common operations.
"""

import base64
import os


class FileUtils:
    """File handling utilities."""
    
    @staticmethod
    def read_binary(filepath):
        """
        Read file in binary mode.
        
        Args:
            filepath (str): Path to file
            
        Returns:
            bytes: File contents
        """
        with open(filepath, 'rb') as f:
            return f.read()
    
    @staticmethod
    def write_binary(filepath, data):
        """
        Write binary data to file.
        
        Args:
            filepath (str): Path to file
            data (bytes): Data to write
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def read_text(filepath):
        """
        Read file in text mode.
        
        Args:
            filepath (str): Path to file
            
        Returns:
            str: File contents
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    
    @staticmethod
    def write_text(filepath, data):
        """
        Write text data to file.
        
        Args:
            filepath (str): Path to file
            data (str): Data to write
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(data)
    
    @staticmethod
    def ensure_directory(directory):
        """
        Create directory if it doesn't exist.
        
        Args:
            directory (str): Directory path
        """
        os.makedirs(directory, exist_ok=True)
    
    @staticmethod
    def file_exists(filepath):
        """
        Check if file exists.
        
        Args:
            filepath (str): Path to check
            
        Returns:
            bool: True if file exists
        """
        return os.path.exists(filepath) and os.path.isfile(filepath)
    
    @staticmethod
    def get_filename(filepath):
        """
        Extract filename from path.
        
        Args:
            filepath (str): Full path
            
        Returns:
            str: Filename only
        """
        return os.path.basename(filepath)
    
    @staticmethod
    def get_file_size(filepath):
        """
        Get file size in bytes.
        
        Args:
            filepath (str): Path to file
            
        Returns:
            int: File size in bytes
        """
        return os.path.getsize(filepath)


class EncodingUtils:
    """Encoding and decoding utilities."""
    
    @staticmethod
    def bytes_to_base64(data):
        """
        Encode bytes to base64 string.
        
        Args:
            data (bytes): Binary data
            
        Returns:
            str: Base64-encoded string
        """
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_to_bytes(encoded):
        """
        Decode base64 string to bytes.
        
        Args:
            encoded (str): Base64-encoded string
            
        Returns:
            bytes: Decoded binary data
        """
        return base64.b64decode(encoded.encode('utf-8'))
    
    @staticmethod
    def bytes_to_hex(data):
        """
        Convert bytes to hex string.
        
        Args:
            data (bytes): Binary data
            
        Returns:
            str: Hex-encoded string
        """
        return data.hex()
    
    @staticmethod
    def hex_to_bytes(hex_string):
        """
        Convert hex string to bytes.
        
        Args:
            hex_string (str): Hex-encoded string
            
        Returns:
            bytes: Binary data
        """
        return bytes.fromhex(hex_string)


class ValidationUtils:
    """Input validation utilities."""
    
    @staticmethod
    def validate_file_path(filepath):
        """
        Validate that file path exists and is readable.
        
        Args:
            filepath (str): Path to validate
            
        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        if not filepath:
            return False, "File path is empty"
        
        if not os.path.exists(filepath):
            return False, f"File does not exist: {filepath}"
        
        if not os.path.isfile(filepath):
            return False, f"Path is not a file: {filepath}"
        
        if not os.access(filepath, os.R_OK):
            return False, f"File is not readable: {filepath}"
        
        return True, ""
    
    @staticmethod
    def validate_directory(directory):
        """
        Validate that directory exists and is writable.
        
        Args:
            directory (str): Directory to validate
            
        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        if not directory:
            return False, "Directory path is empty"
        
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
                return True, ""
            except Exception as e:
                return False, f"Cannot create directory: {str(e)}"
        
        if not os.path.isdir(directory):
            return False, f"Path is not a directory: {directory}"
        
        if not os.access(directory, os.W_OK):
            return False, f"Directory is not writable: {directory}"
        
        return True, ""