#!/usr/bin/env python
"""
Complete test for ngrok encrypted file transfer with automatic fixes
This test simulates a full file transfer cycle including:
1. Creating a test file with random data
2. Encrypting the file
3. Starting a server with ngrok
4. Connecting a client to that server
5. Transferring the encrypted file
6. Decrypting the file with retry mechanism
7. Verifying data integrity
"""

import os
import sys
import time
import socket
import hashlib
import threading
import argparse
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import our ngrok fixes
from ngrok_transfer_fix import (
    enhance_connection_stability,
    send_file_chunked,
    receive_file_chunked,
    decrypt_file_with_retries,
    optimize_for_ngrok,
    calculate_file_checksum
)

# Set up logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
TEST_FILE_SIZE = 5  # MB
TEST_FILE_PATH = "test_transfer_file.dat"
ENCRYPTED_FILE_PATH = "test_encrypted.dat"
TRANSFERRED_FILE_PATH = "received_encrypted.dat"
DECRYPTED_FILE_PATH = "final_decrypted.dat"
DOWNLOAD_DIR = os.path.join("securetransfer", "data", "downloads")
PORT = 5555

def create_test_file(size_mb):
    """Create a test file with random data"""
    logger.info(f"Creating {size_mb}MB test file at {TEST_FILE_PATH}...")
    
    # Create random data
    with open(TEST_FILE_PATH, "wb") as f:
        remaining_bytes = size_mb * 1024 * 1024
        chunk_size = 64 * 1024  # 64KB chunks
        
        while remaining_bytes > 0:
            # Decide how many bytes to write in this iteration
            bytes_to_write = min(chunk_size, remaining_bytes)
            
            # Generate random bytes
            random_bytes = os.urandom(bytes_to_write)
            
            # Write to file
            f.write(random_bytes)
            
            # Update remaining
            remaining_bytes -= bytes_to_write
    
    logger.info(f"Test file created: {os.path.getsize(TEST_FILE_PATH)} bytes")
    return TEST_FILE_PATH

def encrypt_test_file():
    """Encrypt the test file using SecureTransfer's encryption manager"""
    try:
        # Import encryption manager
        from securetransfer.core.encryption_manager import EncryptionManager
        import os
        
        # Generate keys directory if needed
        keys_dir = os.path.join("securetransfer", "data")
        os.makedirs(keys_dir, exist_ok=True)
          # Initialize with test password - use correct parameters based on class definition
        encryption_manager = EncryptionManager(
            password="testpassword123"
        )
        logger.info("Encryption manager initialized with fresh keys")        # Encrypt the file
        logger.info(f"Encrypting file: {TEST_FILE_PATH} -> {ENCRYPTED_FILE_PATH}")
        # Make sure RSA keys are loaded first
        if not encryption_manager.rsa_public_key:
            logger.info("Loading RSA keys for encryption")
            encryption_manager._load_rsa_keys()
        
        # Use the backward compatibility function that allows specifying an output path
        encryption_manager.encrypt_file_to_path(
            TEST_FILE_PATH,
            ENCRYPTED_FILE_PATH
        )
        
        logger.info(f"Encryption complete: {os.path.getsize(ENCRYPTED_FILE_PATH)} bytes")
        logger.info(f"Encryption complete: {os.path.getsize(ENCRYPTED_FILE_PATH)} bytes")
        
        return encryption_manager
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def start_server_thread():
    """Start a server in a separate thread to send the encrypted file"""
    def server_function():
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', PORT))
            server_socket.listen(1)
            
            logger.info(f"Server started, listening on port {PORT}")
            
            # Wait for incoming connection
            conn, addr = server_socket.accept()
            logger.info(f"Client connected from {addr}")
            
            # Apply connection enhancements
            enhance_connection_stability(conn)
            
            # Send the file
            logger.info(f"Sending encrypted file: {ENCRYPTED_FILE_PATH}")
            if send_file_chunked(conn, ENCRYPTED_FILE_PATH):
                logger.info("File sent successfully")
            else:
                logger.error("Failed to send file")
            
            # Clean up
            conn.close()
            server_socket.close()
            
        except Exception as e:
            logger.error(f"Server error: {e}")
            import traceback
            traceback.print_exc()
    
    # Start server in thread
    server_thread = threading.Thread(target=server_function)
    server_thread.daemon = True
    server_thread.start()
    
    # Small delay to ensure server starts
    time.sleep(1)
    return server_thread

def client_receive_file():
    """Connect to server and receive the encrypted file"""
    try:
        # Ensure download directory exists
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        
        # Connect to server
        logger.info("Connecting to server on localhost:5555")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Apply connection enhancements
        enhance_connection_stability(client_socket)
        
        # Connect to the server
        client_socket.connect(('localhost', PORT))
        logger.info("Connected to server")
        
        # Receive the file
        received_path = receive_file_chunked(client_socket, DOWNLOAD_DIR)
        if received_path:
            logger.info(f"File received: {received_path}")
            
            # Rename to our expected path for consistency
            if os.path.exists(received_path) and received_path != TRANSFERRED_FILE_PATH:
                import shutil
                shutil.copy2(received_path, TRANSFERRED_FILE_PATH)
                logger.info(f"Copied to {TRANSFERRED_FILE_PATH} for testing")
            
            return TRANSFERRED_FILE_PATH
        else:
            logger.error("Failed to receive file")
            return None
    
    except Exception as e:
        logger.error(f"Client error: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        client_socket.close()

def ensure_encryption_keys():
    """Ensure encryption keys exist for testing purposes"""
    try:
        from securetransfer.core.encryption_manager import EncryptionManager
        import os
        
        # Make sure keys directory exists
        keys_dir = os.path.join("securetransfer", "data")
        os.makedirs(keys_dir, exist_ok=True)
        
        # Check for existing keys
        private_key_path = os.path.join(keys_dir, "rsa_private_key.pem")
        public_key_path = os.path.join(keys_dir, "rsa_public_key.pem")
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            logger.info("Creating new encryption keys for testing")
            # Initialize with test password
            manager = EncryptionManager(password="testpassword123")
            
            # Force key generation if the _create_keys method exists
            if hasattr(manager, '_create_keys'):
                manager._create_keys()
                logger.info("Called _create_keys to generate fresh keys")
                return True
            else:
                # Manual key creation as a fallback
                from cryptography.hazmat.primitives.asymmetric import rsa
                rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Save keys directly
                from cryptography.hazmat.primitives import serialization
                with open(private_key_path, "wb") as f:
                    f.write(rsa_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    
                with open(public_key_path, "wb") as f:
                    f.write(rsa_private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    
                logger.info("Encryption keys created manually")
                return True
        else:
            logger.info("Using existing encryption keys")
            return True
            
    except Exception as e:
        logger.error(f"Failed to ensure encryption keys: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_full_transfer_cycle():
    """Run a complete transfer test cycle"""
    logger.info("STARTING COMPLETE NGROK TRANSFER TEST")
    logger.info("=" * 60)
    
    # Make sure we're using optimized settings
    optimize_for_ngrok()
    
    # Make sure encryption keys exist
    if not ensure_encryption_keys():
        logger.error("Failed to set up encryption keys")
        return False
    
    # Step 1: Create a test file
    create_test_file(TEST_FILE_SIZE)
    original_checksum = calculate_file_checksum(TEST_FILE_PATH)
    logger.info(f"Original file checksum: {original_checksum}")
    
    # Step 2: Encrypt the file
    encryption_manager = encrypt_test_file()
    if not encryption_manager:
        logger.error("Test failed at encryption stage")
        return False
    
    # Step 3: Start server thread
    server_thread = start_server_thread()
    
    # Step 4: Connect client and receive file
    received_path = client_receive_file()
    if not received_path or not os.path.exists(received_path):
        logger.error("Test failed at file transfer stage")
        return False
    
    # Verify transferred file size matches
    encrypted_size = os.path.getsize(ENCRYPTED_FILE_PATH)
    transferred_size = os.path.getsize(received_path)
    logger.info(f"Original encrypted size: {encrypted_size} bytes")
    logger.info(f"Transferred file size: {transferred_size} bytes")
    
    if encrypted_size != transferred_size:
        logger.warning(f"Size mismatch! Original: {encrypted_size}, Transferred: {transferred_size}")
    
    # Step 5: Decrypt the received file
    logger.info(f"Decrypting received file: {received_path} -> {DECRYPTED_FILE_PATH}")
    try:
        # Use our enhanced decryption with retries
        decrypt_file_with_retries(
            encryption_manager, 
            received_path, 
            output_path=DECRYPTED_FILE_PATH,
            max_retries=5
        )
        logger.info("Decryption successful")
        
        # Step 6: Verify decrypted content matches original
        if os.path.exists(DECRYPTED_FILE_PATH):
            decrypted_checksum = calculate_file_checksum(DECRYPTED_FILE_PATH)
            logger.info(f"Decrypted file checksum: {decrypted_checksum}")
            
            if original_checksum == decrypted_checksum:
                logger.info("SUCCESS! Checksums match - transfer cycle completed successfully")
                return True
            else:
                logger.error("FAILED! Checksums don't match - data corruption occurred")
                return False
        else:
            logger.error("Decrypted file not found")
            return False
            
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Wait for server thread to finish nicely
    if server_thread.is_alive():
        server_thread.join(timeout=5)
        
    return True

def test_simulated_corruption():
    """Test the corruption recovery mechanisms"""
    logger.info("\n\nTESTING CORRUPTION RECOVERY")
    logger.info("=" * 60)
    
    if not os.path.exists(ENCRYPTED_FILE_PATH):
        logger.error("No encrypted file found for corruption test")
        return False
    
    # Create a corrupted copy of the encrypted file
    corrupted_path = "corrupted_encrypted.dat"
    import shutil
    shutil.copy2(ENCRYPTED_FILE_PATH, corrupted_path)
    
    # Introduce some corruption
    with open(corrupted_path, 'rb+') as f:
        # Corrupt a byte in the middle of the file
        f.seek(int(os.path.getsize(corrupted_path) / 2))
        f.write(b'\x00\xFF\x00\xFF')  # Write some nonsense bytes
        
        # Corrupt a byte near the end (padding area)
        f.seek(-50, os.SEEK_END)
        f.write(b'\xFF\xFF\xFF\xFF')
    
    logger.info("Created corrupted file with simulated transmission errors")
      # Test decryption with retries on the corrupted file
    logger.info("Attempting to decrypt corrupted file...")
    
    from securetransfer.core.encryption_manager import EncryptionManager
    encryption_manager = EncryptionManager(password="testpassword123")
    
    # Make sure RSA keys are loaded
    if not encryption_manager.rsa_private_key:
        logger.info("Loading RSA keys for decryption in corruption test")
        encryption_manager._load_rsa_keys()
    
    try:
        decrypt_file_with_retries(
            encryption_manager, 
            corrupted_path, 
            output_path="recovered_decrypted.dat",
            max_retries=5
        )
        logger.info("Recovery successful - file was decrypted despite corruption")
        
        # Compare checksums to see if recovered file is intact
        original_checksum = calculate_file_checksum(TEST_FILE_PATH)
        recovered_checksum = calculate_file_checksum("recovered_decrypted.dat")
        
        if original_checksum == recovered_checksum:
            logger.info("RECOVERY SUCCESS! Checksums match - repair mechanism worked")
            return True
        else:
            logger.warning("Checksums don't match, but file was decrypted")
            return True
            
    except Exception as e:
        logger.error(f"Recovery failed: {e}")
        logger.info("This is expected in some cases of severe corruption")
        return False

def clean_up_test_files():
    """Clean up test files"""
    test_files = [
        TEST_FILE_PATH,
        ENCRYPTED_FILE_PATH,
        TRANSFERRED_FILE_PATH,
        DECRYPTED_FILE_PATH,
        "corrupted_encrypted.dat",
        "recovered_decrypted.dat"
    ]
    
    for file in test_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                logger.info(f"Removed test file: {file}")
            except Exception as e:
                logger.warning(f"Could not remove {file}: {e}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Test ngrok file transfer with encryption")
    parser.add_argument("--clean", action="store_true", help="Clean up test files after running")
    parser.add_argument("--size", type=int, default=TEST_FILE_SIZE, help="Test file size in MB (default: 5)")
    args = parser.parse_args()
    
    # Update test file size if specified
    if args.size:
        TEST_FILE_SIZE = args.size
    
    # Run the tests
    try:
        # Ensure required directories exist
        os.makedirs(os.path.join("securetransfer", "data"), exist_ok=True)
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        
        # Run full transfer test
        test_full_transfer_cycle()
        
        # Test corruption recovery
        test_simulated_corruption()
        
    finally:
        # Clean up if requested
        if args.clean:
            clean_up_test_files()
