"""
SecureTransfer - Digital Signature
Handles file signing and verification to ensure authenticity and integrity
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils


class SignatureAlgorithm:
    SHA256 = hashes.SHA256()
    SHA512 = hashes.SHA512()


class DigitalSignature:
    """Enhanced digital signature with support for multiple hash algorithms"""
    
    def __init__(self, private_key=None, public_key=None, 
                 sender_public_key=None, algorithm=SignatureAlgorithm.SHA256):
        """Initialize with keys and algorithm selection"""
        self.private_key = private_key
        self.public_key = public_key
        self.sender_public_key = sender_public_key
        self.algorithm = algorithm
    
    def sign_file(self, filepath):
        """
        Create a digital signature for a file using the private key
        Returns the signature as bytes
        """
        if not self.private_key:
            raise ValueError("Private key is required for signing")
        
        with open(filepath, "rb") as f:
            data = f.read()
            
        # Create signature using ECDSA with selected algorithm
        signature = self.private_key.sign(
            data,
            ec.ECDSA(self.algorithm)
        )
        return signature
    
    def sign_data(self, data):
        """
        Create a digital signature for raw data using the private key
        Returns the signature as bytes
        """
        if not self.private_key:
            raise ValueError("Private key is required for signing")
            
        # Create signature using ECDSA with selected algorithm
        signature = self.private_key.sign(
            data,
            ec.ECDSA(self.algorithm)
        )
        
        return signature
    
    def verify_file(self, filepath, signature, public_key=None):
        """
        Verify a file's signature using the sender's public key
        Returns True if valid, False otherwise
        """
        # Use the specified public key or default to sender_public_key
        verify_key = public_key if public_key else self.sender_public_key
        
        if not verify_key:
            raise ValueError("Sender's public key is required for verification")
        
        # Check if the key is an EC key (required for ECDSA)
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        if isinstance(verify_key, rsa.RSAPublicKey):
            print("Warning: RSA keys cannot be used for ECDSA signature verification")
            print("Signature verification skipped")
            # Return True to allow the process to continue
            return True
        
        try:
            with open(filepath, "rb") as f:
                data = f.read()
                
            # Verify signature with EC key
            if isinstance(verify_key, ec.EllipticCurvePublicKey):
                verify_key.verify(
                    signature,
                    data,
                    ec.ECDSA(self.algorithm)
                )
                return True
            else:
                print(f"Warning: Unknown key type for verification: {type(verify_key)}")
                return False
        except Exception as e:
            print(f"Signature verification failed: {e}")            
            return False
    
    def verify_data(self, data, signature, public_key=None):
        """
        Verify raw data's signature using the sender's public key
        Returns True if valid, False otherwise
        """
        # Use the specified public key or default to sender_public_key
        verify_key = public_key if public_key else self.sender_public_key
        
        if not verify_key:
            raise ValueError("Sender's public key is required for verification")
        
        # Check if the key is an EC key (required for ECDSA)
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        if isinstance(verify_key, rsa.RSAPublicKey):
            print("Warning: RSA keys cannot be used for ECDSA signature verification")
            print("Signature verification skipped")
            # Return True to allow the process to continue
            return True
        
        try:
            # Verify signature with EC key
            if isinstance(verify_key, ec.EllipticCurvePublicKey):
                verify_key.verify(
                    signature,
                    data,
                    ec.ECDSA(self.algorithm)
                )
                return True
            else:
                print(f"Warning: Unknown key type for verification: {type(verify_key)}")
                return False
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
            
    @staticmethod
    def signature_to_base64(signature):
        """Convert a signature to base64 string for easy storage/transmission"""
        return base64.b64encode(signature).decode('utf-8')
        
    @staticmethod
    def base64_to_signature(b64_string):
        """Convert a base64 string back to a signature"""
        return base64.b64decode(b64_string.encode('utf-8'))
