"""
SecureTransfer - File Processor
Handles file operations including splitting, merging, compression, and verification
"""

import os
import json
import uuid
import time
import hashlib
import zipfile
import shutil
import base64


class FileProcessor:
    """Enhanced file handling with improved security features and metadata"""
    def __init__(self, digital_signature=None, encryption_manager=None, chunk_size=2*1024*1024):
        """Initialize with security components and chunk size (default 2MB)"""
        self.digital_signature = digital_signature
        self.encryption_manager = encryption_manager
        self.chunk_size = chunk_size
        self.progress_callback = None
        self.enable_encryption = True  # Default to enabled
        
        # Check if encryption manager is properly initialized with RSA keys
        self.encryption_available = False
        if self.encryption_manager and hasattr(self.encryption_manager, 'rsa_public_key'):
            from cryptography.hazmat.primitives.asymmetric import rsa
            if isinstance(self.encryption_manager.rsa_public_key, rsa.RSAPublicKey):
                self.encryption_available = True
    
    def set_progress_callback(self, callback):
        """Set a callback function to report progress: callback(current, total, status_message)"""
        self.progress_callback = callback
    
    def calculate_checksum(self, filepath):
        """Calculate SHA-256 checksum of a file"""
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            # Process the file in chunks to handle large files efficiently
            while chunk := f.read(8192):
                sha256.update(chunk)
                
        return sha256.hexdigest()
    
    def create_zip(self, file_list, zip_path):
        """Create a ZIP archive containing multiple files"""
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            for file in file_list:
                arcname = os.path.basename(file)
                zipf.write(file, arcname=arcname)
                
                if self.progress_callback:
                    self.progress_callback(file_list.index(file) + 1, len(file_list), 
                                         f"Adding {arcname} to archive")
    
    def extract_zip(self, zip_path, extract_to):
        """Extract a ZIP archive to the specified directory"""
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            file_list = zipf.namelist()
            
            for i, file in enumerate(file_list):
                zipf.extract(file, path=extract_to)
                
                if self.progress_callback:
                    self.progress_callback(i + 1, len(file_list), 
                                         f"Extracting {file}")
    
    def prepare_file(self, filepath):
        """
        Prepare a file for transfer:
        1. Calculate checksum
        2. Create digital signature (if available)
        3. Create metadata
        4. Package everything into a transfer directory
        
        Returns a transfer_id and directory path containing prepared files
        """
        # Generate a unique ID for this transfer
        transfer_id = str(uuid.uuid4())
        transfer_dir = os.path.join("securetransfer", "data", "transfers", transfer_id)
        os.makedirs(transfer_dir, exist_ok=True)
        
        # Calculate checksum
        checksum = self.calculate_checksum(filepath)
        
        # Create metadata
        metadata = {
            "filename": os.path.basename(filepath),
            "original_path": filepath,
            "size": os.path.getsize(filepath),
            "checksum": checksum,
            "transfer_id": transfer_id,
            "timestamp": time.time(),
            "chunks": 0,  # Will be updated later
            "signature": None  # Will be updated if available
        }
        
        # Copy file to transfer directory
        file_copy = os.path.join(transfer_dir, os.path.basename(filepath))
        shutil.copy2(filepath, file_copy)
          # Create digital signature if available
        if self.digital_signature:
            try:
                signature = self.digital_signature.sign_file(file_copy)
                signature_file = os.path.join(transfer_dir, "signature.bin")
                with open(signature_file, "wb") as f:
                    f.write(signature)
                
                # Store the signature in metadata as base64
                metadata["signature"] = base64.b64encode(signature).decode('utf-8')
                
                # Embed the sender's EC public key in metadata for automatic signature verification
                if self.digital_signature.public_key:
                    from ..core.encryption_manager import public_encode_to_string
                    metadata["sender_ec_public_key"] = public_encode_to_string(self.digital_signature.public_key)
                    print("Embedded sender's EC public key for automatic signature verification")
                    
            except Exception as e:
                print(f"Warning: Could not create signature: {e}")
        
        # Write metadata to JSON file
        with open(os.path.join(transfer_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        return transfer_id, transfer_dir
    def split_file(self, filepath, recipient_public_key=None):
        """
        Split a file into chunks for transfer:
        1. Prepare file (checksum, signature, metadata)
        2. Split into chunks of the configured size
        3. Optionally encrypt chunks if encryption is enabled
        
        Returns the transfer_id
        """
        # Prepare the file first
        transfer_id, transfer_dir = self.prepare_file(filepath)
        
        # Get metadata
        with open(os.path.join(transfer_dir, "metadata.json"), "r") as f:
            metadata = json.load(f)
        
        # Create a chunks directory
        chunks_dir = os.path.join(transfer_dir, "chunks")
        os.makedirs(chunks_dir, exist_ok=True)
        
        # Get the file copy path
        file_copy = os.path.join(transfer_dir, os.path.basename(filepath))
        
        # Split the file
        chunk_index = 0
        total_size = metadata["size"]
        processed_size = 0
        
        # Flag to track if encryption is used
        encryption_used = False
        
        with open(file_copy, 'rb') as f:
            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break
                    
                chunk_name = f"chunk_{chunk_index:04d}.bin"
                chunk_path = os.path.join(chunks_dir, chunk_name)
                
                # Write the chunk
                with open(chunk_path, 'wb') as chunk_file:
                    chunk_file.write(chunk_data)
                
                # Encrypt the chunk if encryption is enabled and we have a recipient key
                if self.enable_encryption and self.encryption_manager and recipient_public_key:
                    if self.progress_callback:
                        self.progress_callback(processed_size, total_size, 
                                            f"Encrypting chunk {chunk_index+1}")
                    
                    # Encrypt the chunk file
                    encrypted_path = self.encryption_manager.encrypt_file(chunk_path, recipient_public_key)
                    
                    # Replace the original chunk with the encrypted one
                    os.remove(chunk_path)
                    os.rename(encrypted_path, chunk_path)
                    encryption_used = True
                
                processed_size += len(chunk_data)
                chunk_index += 1
                
                # Update progress if callback is set
                if self.progress_callback:
                    self.progress_callback(processed_size, total_size, 
                                         f"Processing chunk {chunk_index}")
          # Update metadata with chunk count and encryption info
        metadata["chunks"] = chunk_index
        metadata["encrypted"] = encryption_used
        
        # Add encryption details to metadata if used
        if encryption_used:
            metadata["encryption"] = {
                "method": "AES-256",
                "mode": "CFB",
                "key_exchange": "RSA-OAEP"
            }
        
        with open(os.path.join(transfer_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
            
        # Create a ZIP archive of the entire transfer directory
        package_path = os.path.join(transfer_dir, f"{transfer_id}.zip")
        self.create_zip([
            os.path.join(transfer_dir, "metadata.json"),
            *[os.path.join(chunks_dir, f) for f in os.listdir(chunks_dir)]
        ], package_path)
        
        return transfer_id
    def merge_chunks(self, transfer_dir, output_dir=None):
        """
        Merge chunks back into the original file:
        1. Read metadata
        2. Verify all chunks are present
        3. Decrypt chunks if they're encrypted
        4. Merge chunks
        5. Verify checksum and signature
        
        Returns the path to the reconstructed file
        """
        # Default output directory
        if not output_dir:
            output_dir = os.path.join("securetransfer", "data", "downloads")
            os.makedirs(output_dir, exist_ok=True)
        
        # Get metadata
        metadata_path = os.path.join(transfer_dir, "metadata.json")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file not found in {transfer_dir}")
            
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        # Get info from metadata
        original_filename = metadata["filename"]
        expected_checksum = metadata["checksum"]
        expected_chunks = metadata["chunks"]
        is_encrypted = metadata.get("encrypted", False)
          
        # Output file path
        output_path = os.path.join(output_dir, original_filename)
        
        # Check that all chunks are present - they are in the transfer_dir directly after extraction
        chunks_dir = os.path.join(transfer_dir, "chunks")
        if os.path.exists(chunks_dir):
            chunk_location = chunks_dir
        else:
            # Fallback if chunks were extracted directly to transfer_dir
            chunk_location = transfer_dir
            
        found_chunks = [f for f in os.listdir(chunk_location) if f.startswith("chunk_")]
        if len(found_chunks) != expected_chunks:
            raise ValueError(f"Expected {expected_chunks} chunks, but found {len(found_chunks)}")
        
        # Sort chunks by index
        found_chunks.sort()
        
        # Decrypt chunks if they're encrypted
        if is_encrypted:
            if not self.encryption_manager:
                raise ValueError("File is encrypted but no encryption manager is available")
            
            for i, chunk_name in enumerate(found_chunks):
                chunk_path = os.path.join(chunk_location, chunk_name)
                
                if self.progress_callback:
                    self.progress_callback(i, len(found_chunks), f"Decrypting chunk {i+1}/{len(found_chunks)}")
                
                # Decrypt the chunk
                decrypted_path = self.encryption_manager.decrypt_file(chunk_path)
                
                # Replace the encrypted chunk with the decrypted one
                os.remove(chunk_path)
                os.rename(decrypted_path, chunk_path)
          
        # Merge chunks
        with open(output_path, 'wb') as output_file:
            total_chunks = len(found_chunks)
            
            for i, chunk_name in enumerate(found_chunks):
                chunk_path = os.path.join(chunk_location, chunk_name)
                
                if self.progress_callback:
                    self.progress_callback(i, total_chunks, f"Merging chunk {i+1}/{total_chunks}")
                
                with open(chunk_path, 'rb') as chunk_file:
                    chunk_data = chunk_file.read()
                    output_file.write(chunk_data)
                
                # Update progress if callback is set
                if self.progress_callback:
                    self.progress_callback(i + 1, expected_chunks, 
                                         f"Merging chunk {i+1}/{expected_chunks}")
          # Verify checksum
        actual_checksum = self.calculate_checksum(output_path)
        if actual_checksum != expected_checksum:
            os.remove(output_path)
            raise ValueError(f"Checksum verification failed: expected {expected_checksum}, got {actual_checksum}")
        
        # Verify signature if available
        if "signature" in metadata and metadata["signature"] and self.digital_signature:
            signature_data = base64.b64decode(metadata["signature"])
            
            try:
                # Check if we have a valid EC public key for verification
                from cryptography.hazmat.primitives.asymmetric import ec, rsa
                
                # Progress update
                if self.progress_callback:
                    self.progress_callback(expected_chunks, expected_chunks, "Verifying digital signature...")
                  # Try to use embedded EC public key first (for automatic verification)
                embedded_ec_key = None
                if "sender_ec_public_key" in metadata and metadata["sender_ec_public_key"]:
                    try:
                        from ..core.encryption_manager import public_decode_from_string
                        embedded_ec_key = public_decode_from_string(metadata["sender_ec_public_key"])
                        if self.progress_callback:
                            self.progress_callback(expected_chunks, expected_chunks, "Using embedded EC public key for automatic signature verification...")
                        print("Using embedded sender's EC public key for signature verification")
                        
                        # Temporarily set the embedded EC key for verification
                        original_sender_key = self.digital_signature.sender_public_key
                        self.digital_signature.sender_public_key = embedded_ec_key
                        
                        is_valid = self.digital_signature.verify_file(output_path, signature_data)
                        
                        # Restore original sender key
                        self.digital_signature.sender_public_key = original_sender_key
                        
                        if not is_valid:
                            if self.progress_callback:
                                self.progress_callback(expected_chunks, expected_chunks, "ERROR: Signature verification failed")
                            os.remove(output_path)
                            raise ValueError("Signature verification failed")
                        else:
                            if self.progress_callback:
                                self.progress_callback(expected_chunks, expected_chunks, "Signature verified successfully")
                        
                    except Exception as e:
                        print(f"Could not load or verify with embedded EC public key: {e}")
                        embedded_ec_key = None
                        # Continue to fallback verification methods
                
                # Fallback 1: Use manual EC key if available and embedded key failed
                if embedded_ec_key is None and self.digital_signature.sender_public_key and isinstance(self.digital_signature.sender_public_key, ec.EllipticCurvePublicKey):
                    # We have a proper EC key for signature verification
                    if self.progress_callback:
                        self.progress_callback(expected_chunks, expected_chunks, "Using manually provided EC public key for signature verification...")
                    
                    is_valid = self.digital_signature.verify_file(output_path, signature_data)
                    
                    if not is_valid:
                        if self.progress_callback:
                            self.progress_callback(expected_chunks, expected_chunks, "ERROR: Signature verification failed")
                        os.remove(output_path)
                        raise ValueError("Signature verification failed")
                    else:
                        if self.progress_callback:
                            self.progress_callback(expected_chunks, expected_chunks, "Signature verified successfully")
                
                # Fallback 2: Handle RSA key case
                elif embedded_ec_key is None and self.digital_signature.sender_public_key and isinstance(self.digital_signature.sender_public_key, rsa.RSAPublicKey):
                    # We have an RSA key which can't be used for EC signature verification
                    msg = "Warning: Sender provided an RSA key which cannot be used for signature verification"
                    if self.progress_callback:
                        self.progress_callback(expected_chunks, expected_chunks, msg)
                    print(msg)
                    print("Using checksum verification only")
                
                # Fallback 3: No valid key available
                elif embedded_ec_key is None:
                    msg = "Warning: Cannot verify signature - valid sender's EC public key not available"
                    if self.progress_callback:
                        self.progress_callback(expected_chunks, expected_chunks, msg)
                    print(msg)
                    print("Using checksum verification only")
            except Exception as e:
                msg = f"Signature verification skipped due to error: {e}"
                if self.progress_callback:
                    self.progress_callback(expected_chunks, expected_chunks, msg)
                print(msg)
                print("Using checksum verification only")
        
        return output_path
    
    def verify_transfer(self, transfer_id):
        """
        Verify if a transfer is complete and valid:
        1. Check if all chunks are present
        2. Check if metadata is complete
        
        Returns True if valid, False otherwise
        """
        transfer_dir = os.path.join("securetransfer", "data", "transfers", transfer_id)
        
        try:
            # Check metadata
            with open(os.path.join(transfer_dir, "metadata.json"), "r") as f:
                metadata = json.load(f)
            
            # Check chunks
            chunks_dir = os.path.join(transfer_dir, "chunks")
            expected_chunks = metadata.get("chunks", 0)
            found_chunks = [f for f in os.listdir(chunks_dir) if f.startswith("chunk_")]
            
            # All chunks must be present
            return len(found_chunks) == expected_chunks
            
        except Exception as e:
            print(f"Transfer verification failed: {e}")
            return False
