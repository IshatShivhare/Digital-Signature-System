"""
qr_module.py
QR code generation for public key sharing and signature distribution.
"""

import qrcode
from io import BytesIO
from PIL import Image
from utils import FileUtils


class QRCodeGenerator:
    """Generate QR codes for cryptographic data."""
    
    @staticmethod
    def generate_qr_for_public_key(public_key_pem, output_path=None):
        """
        Generate QR code containing public key in PEM format.
        
        Args:
            public_key_pem (bytes): Public key in PEM format
            output_path (str): Optional path to save QR code image
            
        Returns:
            Image: PIL Image object containing QR code
        """
        qr = qrcode.QRCode(
            version=None,  # Auto-size
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # Convert PEM to string
        pem_str = public_key_pem.decode('utf-8') if isinstance(public_key_pem, bytes) else public_key_pem
        
        qr.add_data(pem_str)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            img.save(output_path)
        
        return img
    
    @staticmethod
    def generate_qr_for_fingerprint(fingerprint, output_path=None):
        """
        Generate QR code containing public key fingerprint.
        
        Args:
            fingerprint (str): SHA-256 fingerprint of public key
            output_path (str): Optional path to save QR code image
            
        Returns:
            Image: PIL Image object containing QR code
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        
        qr.add_data(fingerprint)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            img.save(output_path)
        
        return img
    
    @staticmethod
    def generate_qr_for_signature_info(metadata, output_path=None):
        """
        Generate QR code containing signature metadata summary.
        
        Args:
            metadata (dict): Signature metadata
            output_path (str): Optional path to save QR code image
            
        Returns:
            Image: PIL Image object containing QR code
        """
        # Create compact signature info
        info = (
            f"File: {metadata['file_name']}\n"
            f"Timestamp: {metadata['timestamp']}\n"
            f"Algorithm: {metadata['algorithm']}\n"
            f"Fingerprint: {metadata['public_key_fingerprint']}"
        )
        
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        
        qr.add_data(info)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            img.save(output_path)
        
        return img
    
    @staticmethod
    def read_public_key_from_qr(image_path):
        """
        Read public key PEM from QR code image.
        
        Args:
            image_path (str): Path to QR code image
            
        Returns:
            str: Public key PEM string or None if failed
        """
        try:
            from pyzbar.pyzbar import decode
            
            img = Image.open(image_path)
            decoded_objects = decode(img)
            
            if decoded_objects:
                data = decoded_objects[0].data.decode('utf-8')
                # Verify it looks like a PEM key
                if '-----BEGIN PUBLIC KEY-----' in data:
                    return data
            
            return None
            
        except ImportError:
            print("Warning: pyzbar not installed. QR scanning disabled.")
            return None
        except Exception as e:
            print(f"Error reading QR code: {str(e)}")
            return None
    
    @staticmethod
    def create_qr_grid(public_key_path, fingerprint, metadata, output_dir):
        """
        Create a grid of QR codes for comprehensive sharing.
        
        Args:
            public_key_path (str): Path to public key PEM file
            fingerprint (str): Public key fingerprint
            metadata (dict): Signature metadata
            output_dir (str): Directory to save QR codes
            
        Returns:
            dict: Paths to generated QR codes
        """
        FileUtils.ensure_directory(output_dir)
        
        # Read public key
        public_key_pem = FileUtils.read_binary(public_key_path)
        
        # Generate individual QR codes
        qr_paths = {}
        
        # Full public key QR
        qr_key_path = f"{output_dir}/qr_public_key.png"
        QRCodeGenerator.generate_qr_for_public_key(public_key_pem, qr_key_path)
        qr_paths['public_key'] = qr_key_path
        
        # Fingerprint QR
        qr_fp_path = f"{output_dir}/qr_fingerprint.png"
        QRCodeGenerator.generate_qr_for_fingerprint(fingerprint, qr_fp_path)
        qr_paths['fingerprint'] = qr_fp_path
        
        # Signature info QR
        qr_sig_path = f"{output_dir}/qr_signature_info.png"
        QRCodeGenerator.generate_qr_for_signature_info(metadata, qr_sig_path)
        qr_paths['signature_info'] = qr_sig_path
        
        return qr_paths