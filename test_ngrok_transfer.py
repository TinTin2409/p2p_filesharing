#!/usr/bin/env python
"""
Test script for validating ngrok transfer fixes in SecureTransfer
This script tests the reliability of encrypted file transfers over ngrok tunnels
"""

import os
import sys
import time
import hashlib
import random
import argparse
from datetime import datetime

# Try to import ngrok transfer fix module
try:
    from ngrok_transfer_fix import (
        enhance_connection_stability, 
        send_file_chunked,
        receive_file_chunked,
        decrypt_file_with_retries,
        is_ngrok_connection,
        optimize_for_ngrok
    )
    NGROK_FIX_AVAILABLE = True
except ImportError:
    print("Warning: ngrok_transfer_fix module not available")
    NGROK_FIX_AVAILABLE = False

# Create a test file of specified size filled with random data
def create_test_file(size_mb, output_path="test_file.dat"):
    """Create a test file with random data"""
    print(f"Creating {size_mb}MB test file at {output_path}...")
    
    # Create random data
    with open(output_path, "wb") as f:
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
            
            # Print progress
            progress = 100 - int(remaining_bytes * 100 / (size_mb * 1024 * 1024))
            if progress % 10 == 0:
                print(f"Progress: {progress}%")
    
    print(f"Test file created: {os.path.getsize(output_path)} bytes")
    return output_path

# Calculate file hash for verification
def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Test encryption and decryption with the SecureTransfer system
def test_encryption_decryption(input_file, output_file="encrypted.bin", decrypted_file="decrypted.dat"):
    """Test encryption and decryption using the SecureTransfer system"""
    print("\nTesting encryption and decryption...")
    try:
        # Import the encryption manager
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))
        from securetransfer.core.encryption_manager import EncryptionManager
        
        # Make sure directories exist
        os.makedirs(os.path.join("securetransfer", "data"), exist_ok=True)
        
        # Initialize encryption manager with a test password
        encryption_manager = EncryptionManager(password="testpassword123")
        # Keys are generated automatically during initialization
        
        # Make sure RSA keys are loaded
        if not encryption_manager.rsa_public_key:
            print("Loading RSA keys for encryption")
            encryption_manager._load_rsa_keys()
        
        # Calculate original file hash
        original_hash = calculate_file_hash(input_file)
        print(f"Original file hash: {original_hash}")
        
        # Encrypt the file
        print(f"Encrypting file: {input_file} -> {output_file}")
        encryption_manager.encrypt_file_to_path(input_file, output_file)
        print(f"Encryption complete: {os.path.getsize(output_file)} bytes")
        
        # Decrypt the file
        print(f"Decrypting file: {output_file} -> {decrypted_file}")
        
        # Use ngrok fixes if available
        if NGROK_FIX_AVAILABLE:
            print("Using ngrok-optimized decryption with retries")
            decrypt_file_with_retries(encryption_manager, output_file, output_path=decrypted_file, max_retries=5)
        else:
            encryption_manager.decrypt_file(output_file, decrypted_file)
            
        print(f"Decryption complete: {os.path.getsize(decrypted_file)} bytes")
        
        # Verify decrypted file hash matches original
        decrypted_hash = calculate_file_hash(decrypted_file)
        print(f"Decrypted file hash: {decrypted_hash}")
        
        if original_hash == decrypted_hash:
            print("SUCCESS: File hash verification passed!")
            return True
        else:
            print("ERROR: File hash verification failed!")
            return False
            
    except Exception as e:
        print(f"ERROR in encryption test: {e}")
        import traceback
        traceback.print_exc()
        return False

# Simulate ngrok transfer issues
def simulate_ngrok_transfer_issues(encrypted_file, output_file="ngrok_simulated.bin"):
    """Simulate common ngrok transfer issues by corrupting the file in specific ways"""
    print("\nSimulating ngrok transfer issues...")
    
    try:
        # Copy the encrypted file
        with open(encrypted_file, "rb") as src:
            data = src.read()
        
        # Introduce common ngrok transfer issues
        modified_data = bytearray(data)
        file_size = len(modified_data)
        
        # 1. Corrupt a few random bytes (random bit flips)
        for _ in range(5):
            pos = random.randint(0, file_size - 1)
            bit_pos = random.randint(0, 7)
            modified_data[pos] ^= (1 << bit_pos)  # Flip a random bit
        
        # 2. Duplicate a small chunk (2KB) at a random position
        if file_size > 4096:
            pos = random.randint(2048, file_size - 2048)
            chunk = modified_data[pos:pos+2048]
            modified_data[pos:pos] = chunk  # Insert duplicate chunk
        
        # Write the modified file
        with open(output_file, "wb") as dst:
            dst.write(modified_data)
        
        print(f"Simulated ngrok transfer issues: {encrypted_file} -> {output_file}")
        print(f"Modified file size: {os.path.getsize(output_file)} bytes")
        
        return output_file
    
    except Exception as e:
        print(f"ERROR in simulation: {e}")
        return None

# Run a complete test
def run_complete_test(file_size_mb=10):
    """Run a complete test of the ngrok transfer fixes"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_dir = f"ngrok_test_{timestamp}"
    os.makedirs(test_dir, exist_ok=True)
    
    print(f"\n=== Starting ngrok transfer fix test ({file_size_mb}MB) ===")
    
    # Step 1: Create test file
    test_file = os.path.join(test_dir, "original.dat")
    create_test_file(file_size_mb, test_file)
    
    # Step 2: Test normal encryption/decryption
    encrypted_file = os.path.join(test_dir, "encrypted.bin")
    decrypted_file = os.path.join(test_dir, "decrypted.dat")
    normal_success = test_encryption_decryption(test_file, encrypted_file, decrypted_file)
    
    # Step 3: Simulate ngrok issues
    corrupted_file = os.path.join(test_dir, "ngrok_simulated.bin")
    simulate_ngrok_transfer_issues(encrypted_file, corrupted_file)
    
    # Step 4: Try to decrypt with ngrok fixes
    fixed_file = os.path.join(test_dir, "fixed.dat")
    
    print("\nAttempting to decrypt corrupted file with ngrok fixes...")
    try:        
        if NGROK_FIX_AVAILABLE:
            # Import encryption manager
            from securetransfer.core.encryption_manager import EncryptionManager
            
            # Make sure directories exist
            os.makedirs(os.path.join("securetransfer", "data"), exist_ok=True)
            
            encryption_manager = EncryptionManager(password="testpassword123")
            # Keys are generated automatically during initialization
            
            # Apply optimization
            optimize_for_ngrok()
            
            # Try to decrypt with retries
            decrypt_file_with_retries(
                encryption_manager, 
                corrupted_file, 
                output_path=fixed_file, 
                max_retries=5
            )
            
            # Verify hash
            original_hash = calculate_file_hash(test_file)
            fixed_hash = calculate_file_hash(fixed_file)
            
            if original_hash == fixed_hash:
                print("SUCCESS: Ngrok fixes successfully recovered the corrupted file!")
                ngrok_fix_success = True
            else:
                print("ERROR: Ngrok fixes could not fully recover the corrupted file")
                ngrok_fix_success = False
        else:
            print("Cannot test ngrok fixes - module not available")
            ngrok_fix_success = False
            
    except Exception as e:
        print(f"ERROR in ngrok fix test: {e}")
        ngrok_fix_success = False
    
    # Print summary
    print("\n=== Test Summary ===")
    print(f"Normal encryption/decryption: {'SUCCESS' if normal_success else 'FAILED'}")
    print(f"Ngrok fix on corrupted file: {'SUCCESS' if ngrok_fix_success else 'FAILED'}")
    print(f"Test directory: {os.path.abspath(test_dir)}")
    
    if normal_success and ngrok_fix_success:
        print("\nAll tests PASSED! The ngrok transfer fixes are working correctly.")
    else:
        print("\nSome tests FAILED. Please check the logs for details.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test ngrok transfer fixes")
    parser.add_argument("--size", type=int, default=10, help="Test file size in MB")
    args = parser.parse_args()
    
    run_complete_test(args.size)
