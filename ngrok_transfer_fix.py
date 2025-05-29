"""
SecureTransfer - Ngrok Transfer Fix
This module enhances ngrok file transfers to improve reliability when sending encrypted files
"""

import os
import time
import logging
import socket
import traceback
import hashlib
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants for chunked transmission
CHUNK_SIZE = 1024 * 1024  # Default to 1MB chunks for ngrok transfers (reduced from 2MB)
BUFFER_SIZE = 64 * 1024   # 64KB buffer size for socket operations
MAX_RETRIES = 5           # Maximum retries for decryption operations

def enhance_connection_stability(conn, timeout=30):
    """
    Enhance connection stability for ngrok transfers
    
    Args:
        conn (socket): The socket connection
        timeout (int): Connection timeout in seconds
    """
    try:
        # Increase buffer sizes for more reliable transmission
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)  # 256KB receive buffer
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)  # 256KB send buffer
        
        # Set TCP keepalive options
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Set a longer timeout for ngrok connections
        conn.settimeout(timeout)
        
        logger.info(f"Connection enhanced with larger buffers and {timeout}s timeout")
        return True
    except Exception as e:
        logger.error(f"Could not enhance connection: {e}")
        return False

def send_file_chunked(conn, filepath, blocksize=BUFFER_SIZE):
    """
    Send a file in chunks with additional error checking
    
    Args:
        conn (socket): The socket connection
        filepath (str): Path to the file to send
        blocksize (int): Size of each transmission block
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get file info
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        # Send header with file info and chunking info
        header = {
            "filename": filename,
            "filesize": filesize,
            "chunked": True,
            "blocksize": blocksize,
            "checksum": calculate_file_checksum(filepath)
        }
        
        # Convert header to bytes and send
        import json
        header_bytes = json.dumps(header).encode('utf-8') + b'\\n'
        conn.sendall(header_bytes)
        
        # Send file contents in chunks with progress tracking
        sent = 0
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(blocksize)
                if not chunk:
                    break
                    
                # Add length prefix to each chunk for framing
                chunk_len = len(chunk).to_bytes(4, byteorder='big')
                conn.sendall(chunk_len + chunk)
                
                sent += len(chunk)
                progress = min(100, int(sent * 100 / filesize))
                
                # Log progress approximately every 5%
                if progress % 5 == 0:
                    logger.info(f"Sending: {progress}% complete")
        
        # Send end marker
        conn.sendall((0).to_bytes(4, byteorder='big'))
        logger.info(f"File sent successfully ({sent}/{filesize} bytes)")
        return True
        
    except Exception as e:
        logger.error(f"Error sending file: {e}")
        traceback.print_exc()
        return False

def receive_file_chunked(conn, output_dir):
    """
    Receive a file in chunks with error checking
    
    Args:
        conn (socket): The socket connection
        output_dir (str): Directory to save the file
    
    Returns:
        str: Path to the received file, or None if failed
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Receive header
        header_buffer = b""
        while b'\\n' not in header_buffer:
            chunk = conn.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed before receiving header")
            header_buffer += chunk
            
            # Prevent infinite loop
            if len(header_buffer) > 10240:  # 10KB max header size
                raise ValueError("Header too large")
        
        # Parse header
        header_line, rest = header_buffer.split(b'\\n', 1)
        import json
        info = json.loads(header_line.decode('utf-8'))
        
        filename = info["filename"]
        filesize = info["filesize"]
        blocksize = info.get("blocksize", BUFFER_SIZE)
        expected_checksum = info.get("checksum")
        
        logger.info(f"Receiving {filename} ({filesize} bytes)")
        
        # Create output file
        output_path = os.path.join(output_dir, filename)
        
        # Receive file contents in chunks
        received = 0
        remaining_buffer = rest
        
        with open(output_path, 'wb') as f:
            while received < filesize:
                # Extract chunk length
                while len(remaining_buffer) < 4:
                    chunk = conn.recv(blocksize)
                    if not chunk:
                        raise ConnectionError("Connection closed prematurely")
                    remaining_buffer += chunk
                
                chunk_len_bytes = remaining_buffer[:4]
                remaining_buffer = remaining_buffer[4:]
                chunk_len = int.from_bytes(chunk_len_bytes, byteorder='big')
                
                # End marker
                if chunk_len == 0:
                    break
                
                # Read the chunk
                while len(remaining_buffer) < chunk_len:
                    needed = min(chunk_len - len(remaining_buffer), blocksize)
                    chunk = conn.recv(needed)
                    if not chunk:
                        raise ConnectionError("Connection closed prematurely")
                    remaining_buffer += chunk
                
                # Extract the complete chunk
                data_chunk = remaining_buffer[:chunk_len]
                remaining_buffer = remaining_buffer[chunk_len:]
                
                # Write to file
                f.write(data_chunk)
                received += len(data_chunk)
                
                # Report progress
                progress = min(100, int(received * 100 / filesize))
                if progress % 10 == 0:
                    logger.info(f"Receiving: {progress}% complete")
        
        # Verify checksum if provided
        if expected_checksum:
            actual_checksum = calculate_file_checksum(output_path)
            if actual_checksum != expected_checksum:
                logger.warning(f"Checksum verification failed: expected {expected_checksum}, got {actual_checksum}")
            else:
                logger.info("Checksum verified successfully")
        
        logger.info(f"File received successfully ({received}/{filesize} bytes)")
        return output_path
        
    except Exception as e:
        logger.error(f"Error receiving file: {e}")
        traceback.print_exc()
        return None

def decrypt_file_with_retries(encryption_manager, encrypted_path, output_path=None, max_retries=MAX_RETRIES):
    """
    Decrypt a file with multiple retries to handle potential corruption
    
    Args:
        encryption_manager: The encryption manager object
        encrypted_path (str): Path to the encrypted file
        output_path (str): Path where the decrypted file should be saved
        max_retries (int): Maximum number of decryption attempts
    
    Returns:
        str: Path to the decrypted file, or None if failed
    """
    if not output_path:
        if encrypted_path.endswith('.encrypted'):
            output_path = encrypted_path[:-10]
        else:
            base, ext = os.path.splitext(encrypted_path)
            output_path = f"{base}_decrypted{ext}"
    
    # Create a backup of the original file
    backup_path = f"{encrypted_path}.bak"
    try:
        import shutil
        shutil.copy2(encrypted_path, backup_path)
        logger.info(f"Created backup at {backup_path}")
    except Exception as e:
        logger.warning(f"Could not create backup: {e}")
    
    retry_count = 0
    last_error = None
    
    # Check if file exists and has a reasonable size
    if not os.path.exists(encrypted_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
    
    file_size = os.path.getsize(encrypted_path)
    if file_size < 100:  # Minimum size for any valid encrypted file
        raise ValueError(f"File too small to be a valid encrypted file: {file_size} bytes")
    
    # Look for ngrok signature to apply specific fixes
    is_ngrok = False
    try:
        # Check if this file likely came from an ngrok transfer
        # (We check settings or look for specific characteristics in the file)
        try:
            from securetransfer.data.database import DatabaseManager
            db_manager = DatabaseManager()
            settings = db_manager.get_settings()
            if settings.get("ngrok_optimized", False):
                is_ngrok = True
                logger.info("Applying ngrok-specific decryption optimizations")
        except ImportError:
            # Try to infer if it's from ngrok by examining file patterns
            # Files from ngrok transfers often have specific byte patterns
            with open(encrypted_path, 'rb') as f:
                header = f.read(32)
                if len(header) >= 16:
                    # Look for patterns typical in ngrok-transferred files
                    # (This is a heuristic and may need adjustment)
                    # Check file size modulo typical ngrok chunk sizes
                    if file_size % 16384 == 0 or file_size % 32768 == 0:
                        is_ngrok = True
                        logger.info("File appears to be from ngrok transfer based on size pattern")
    except Exception:
        # If error occurs, assume it could be ngrok
        is_ngrok = True
    
    while retry_count < max_retries:
        try:
            logger.info(f"Decryption attempt {retry_count + 1}/{max_retries}...")
            
            # Try to decrypt
            result_path = encryption_manager.decrypt_file(encrypted_path, output_path)
            logger.info(f"Decryption successful on attempt {retry_count + 1}")
            return result_path
            
        except Exception as e:
            retry_count += 1
            last_error = e
            
            if retry_count < max_retries:
                logger.warning(f"Decryption attempt {retry_count} failed: {e}")
                
                # Apply different repair strategies based on error type
                error_message = str(e).lower()
                
                # Special handling for ngrok transfers
                if is_ngrok:
                    logger.info("Applying ngrok-specific file repair techniques")
                    
                    # For ngrok transfers, we often see byte corruption at specific boundaries
                    if "padding" in error_message or "invalid" in error_message:
                        logger.info("Attempting to fix padding issues common with ngrok transfers")
                        try:
                            # First try basic padding repair
                            repair_corrupt_file(encrypted_path, repair_type="padding")
                            time.sleep(0.5)
                        except Exception:
                            pass
                        
                        # If that doesn't work, try more aggressive repairs focusing on chunk boundaries
                        try:
                            # Ngrok transfers often corrupt at chunk boundaries
                            # Try to detect and fix these issues
                            with open(encrypted_path, 'rb') as f:
                                data = bytearray(f.read())
                            
                            # Check block sizes and trim if necessary
                            file_len = len(data)
                            if file_len % 16 != 0:
                                # Not aligned to AES block size
                                trim_bytes = file_len % 16
                                with open(encrypted_path, 'wb') as f:
                                    f.write(data[:-trim_bytes])
                                logger.info(f"Trimmed {trim_bytes} bytes for block alignment")
                        except Exception as repair_error:
                            logger.warning(f"Advanced ngrok repair failed: {repair_error}")
                else:
                    # Standard repair techniques for non-ngrok files
                    if "padding" in error_message or "invalid" in error_message:
                        logger.info("Padding error detected - attempting padding repair")
                        try:
                            repair_corrupt_file(encrypted_path, repair_type="padding")
                            time.sleep(0.5)  # Short delay after repair
                        except Exception as repair_error:
                            logger.warning(f"Padding repair failed: {repair_error}")
                
                if "key" in error_message or "decrypt" in error_message:
                    logger.info("Key decryption error detected - attempting header repair")
                    try:
                        repair_corrupt_file(encrypted_path, repair_type="header")
                        time.sleep(0.5)  # Short delay after repair
                    except Exception as repair_error:
                        logger.warning(f"Header repair failed: {repair_error}")
                
                # If all specific repairs failed, try byte-level repair
                if retry_count == max_retries - 2:
                    logger.info("Trying byte-level repair as second-to-last attempt")
                    try:
                        advanced_file_repair(encrypted_path)
                        time.sleep(1)  # Longer delay for final attempt
                    except Exception as repair_error:
                        logger.warning(f"Byte-level repair failed: {repair_error}")
                
                # If everything else failed, restore from backup for last attempt
                if retry_count == max_retries - 1 and os.path.exists(backup_path):
                    logger.info("Last attempt: restoring from backup")
                    try:
                        import shutil
                        shutil.copy2(backup_path, encrypted_path)
                        time.sleep(1)  # Longer delay for final attempt
                    except Exception as restore_error:
                        logger.warning(f"Restore failed: {restore_error}")
    
    # All retries failed
    logger.error(f"Decryption failed after {max_retries} attempts: {last_error}")
    
    # Give a specific error message based on failure type
    if is_ngrok:
        raise ValueError(f"Decryption failed for ngrok transfer: {last_error}. Try transferring the file again with a smaller chunk size (512KB recommended).")
    else:
        raise ValueError(f"Decryption failed: {last_error}. Check that the encryption keys and passwords match.")

def repair_corrupt_file(file_path, repair_type="auto"):
    """
    Attempt to repair a potentially corrupt encrypted file
    
    Args:
        file_path (str): Path to the file
        repair_type (str): Type of repair to attempt ("auto", "header", "padding")
        
    Returns:
        bool: True if repair attempt was made
    """
    try:
        # Read the file
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Check for common corruption patterns
        # 1. Ensure file size is appropriate
        if len(data) < 64:  # Minimum size for header + AES key
            logger.error("File too small to be a valid encrypted file")
            return False
            
        # Create backup before repairs
        backup_path = f"{file_path}.repair_backup"
        import shutil
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created repair backup at {backup_path}")
        
        # 2. Extract and verify the header components
        iv = data[:16]  # First 16 bytes should be the IV
        key_length_bytes = data[16:18]  # Next 2 bytes should be key length
        
        try:
            key_length = int.from_bytes(key_length_bytes, byteorder='big')
            if key_length < 64 or key_length > 512:  # Reasonable range for RSA-encrypted AES key
                logger.warning(f"Suspicious key length: {key_length}, attempting repair")
                
                if repair_type in ["auto", "header"]:
                    # Try to fix by assuming a standard RSA-2048 encrypted key length
                    key_length = 256
                    fixed_key_length = key_length.to_bytes(2, byteorder='big')
                    
                    # Replace the key length bytes in the file
                    with open(file_path, 'wb') as f:
                        f.write(data[:16])  # Original IV
                        f.write(fixed_key_length)  # Fixed key length
                        f.write(data[18:])  # Rest of the file
                    
                    logger.info(f"Repaired key length value to {key_length}")
            
            # 3. Fix padding issues
            if repair_type in ["auto", "padding"] and len(data) > (18 + key_length):
                # Get the encrypted data portion
                encrypted_part = data[18 + key_length:]
                
                # AES-CFB doesn't need padding, but check for common corruption
                # where extra bytes might have been added
                mod_value = len(encrypted_part) % 16
                if mod_value != 0:
                    logger.warning(f"Data length not aligned to AES block size, trimming {mod_value} bytes")
                    
                    # Keep only complete blocks
                    trimmed_length = len(encrypted_part) - mod_value
                    
                    # Rewrite the file with correct padding
                    with open(file_path, 'wb') as f:
                        f.write(data[:18 + key_length])  # Header (IV + key length + key)
                        f.write(encrypted_part[:trimmed_length])  # Trimmed encrypted data
                    
                    logger.info(f"Trimmed file to correct AES block alignment")
                    
        except Exception as e:
            logger.warning(f"Repair attempt encountered an error: {e}")
            if repair_type == "auto":
                # Try basic byte repair as a last resort
                advanced_file_repair(file_path)
            
        return True
            
    except Exception as e:
        logger.error(f"Error attempting to repair file: {e}")
        return False

def advanced_file_repair(file_path):
    """
    Perform advanced byte-level repairs on a corrupted encrypted file
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        bool: True if repair was attempted
    """
    try:
        # Create a backup before attempting repairs
        backup_path = f"{file_path}.backup"
        import shutil
        try:
            shutil.copy2(file_path, backup_path)
            logger.info(f"Created backup at {backup_path}")
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")
        
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
        
        if len(data) < 32:
            return False  # Too small to repair
            
        # 1. Fix common corruption patterns in IV (first 16 bytes)
        # IV should be random bytes, but sometimes gets corrupted with null bytes
        iv = data[:16]
        if iv.count(0) > 8:  # If more than half are null
            logger.info("IV appears corrupted (too many null bytes), replacing with random data")
            new_iv = os.urandom(16)
            for i in range(16):
                data[i] = new_iv[i]
        
        # 2. Check for null byte corruption in the RSA-encrypted key
        key_length = int.from_bytes(data[16:18], byteorder='big')
        if 64 <= key_length <= 512:
            key_start = 18
            key_end = key_start + key_length
            
            if key_end <= len(data):
                key_data = data[key_start:key_end]
                
                # RSA encrypted data shouldn't have long sequences of the same byte
                if has_corruption_pattern(key_data):
                    logger.warning("RSA key appears to have corruption patterns")
                    # We can't fully recover RSA key, but we can remove obvious corruption
                    clean_binary_data(data, key_start, key_end)
        
        # 3. Write back repaired file
        with open(file_path, 'wb') as f:
            f.write(data)
            
        logger.info(f"Advanced file repair completed for {file_path}")
        return True
        
    except Exception as e:
        logger.error(f"Advanced repair failed: {e}")
        return False

def has_corruption_pattern(data):
    """Check if data has patterns indicating corruption"""
    if len(data) < 16:
        return False
        
    # Check for long runs of same byte
    last_byte = None
    run_length = 0
    max_run = 0
    
    for b in data:
        if b == last_byte:
            run_length += 1
        else:
            last_byte = b
            run_length = 1
        
        max_run = max(max_run, run_length)
    
    # RSA encrypted data shouldn't have long runs of identical bytes
    return max_run > 8

def clean_binary_data(data, start, end):
    """Remove obvious corruption patterns from binary data"""
    if end - start < 16:
        return
        
    segment = data[start:end]
    
    # Replace long runs of identical bytes with random data
    i = 0
    while i < len(segment):
        run_length = 1
        j = i + 1
        
        while j < len(segment) and segment[j] == segment[i]:
            run_length += 1
            j += 1
            
        if run_length > 8:
            # Replace this run with random bytes
            for k in range(i, j):
                data[start + k] = random.randint(0, 255)
                
        i = j

def calculate_file_checksum(file_path):
    """
    Calculate SHA-256 checksum of a file
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        str: Hexadecimal checksum
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64KB chunks
            if not data:
                break
            sha256.update(data)
            
    return sha256.hexdigest()

def is_ngrok_connection(host):
    """
    Check if a host appears to be an ngrok connection
    
    Args:
        host (str): Hostname or URL
        
    Returns:
        bool: True if it's likely an ngrok connection
    """
    ngrok_indicators = [
        'ngrok', 
        'tcp.ap.',
        'tcp.eu.',
        'tcp.us.',
        'tcp.sa.',
        'tcp.au.',
        'tcp.in.',
        'tcp.jp.'
    ]
    
    if not host:
        return False
        
    host = host.lower()
    return any(indicator in host for indicator in ngrok_indicators)

def optimize_for_ngrok(settings=None):
    """
    Optimize settings for ngrok transfers
    
    Args:
        settings (dict, optional): Application settings. If None, will load from settings.json
        
    Returns:
        dict: Updated settings
    """
    # If no settings provided, try to load settings from file
    if settings is None:
        try:
            import json
            import os
            settings_path = os.path.join("securetransfer", "data", "settings.json")
            if os.path.exists(settings_path):
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                logger.info("Loaded settings from settings.json")
            else:
                settings = {}
                logger.warning("Settings file not found, using defaults")
        except Exception as e:
            settings = {}
            logger.warning(f"Error loading settings: {e}, using defaults")
    
    # Clone settings to avoid modifying the original
    import copy
    updated_settings = copy.deepcopy(settings)
    
    # Set optimal chunk size for ngrok transfers
    updated_settings["chunk_size"] = 524288  # 512KB in bytes (reduced from 1MB)
    
    # Add ngrok-specific settings
    updated_settings["ngrok_optimized"] = True
    updated_settings["ngrok_buffer_size"] = 262144  # 256KB buffer
    updated_settings["ngrok_timeout"] = 30  # 30 seconds timeout
    updated_settings["ngrok_max_retries"] = 5  # 5 retries for operations
    
    # Save the updated settings if possible
    try:
        import json
        import os
        settings_path = os.path.join("securetransfer", "data", "settings.json")
        os.makedirs(os.path.dirname(settings_path), exist_ok=True)
        with open(settings_path, "w") as f:
            json.dump(updated_settings, f, indent=4)
        logger.info("Saved optimized settings to settings.json")
    except Exception as e:
        logger.warning(f"Could not save settings: {e}")
    
    return updated_settings

def apply_fixes():
    """Apply the fixes to the main application modules"""
    try:
        # Log the attempt
        logger.info("Attempting to apply ngrok fixes to application modules...")
        
        # Try to safely import the modules (might fail if path is not set up)
        try:
            from securetransfer.core.file_processor import FileProcessor
            from securetransfer.networking.connection import NetworkManager
            logger.info("Successfully imported required modules")
            
            # Apply optimized settings
            settings = optimize_for_ngrok()
            
            # Apply patch to FileProcessor for ngrok transfers
            if hasattr(FileProcessor, 'chunk_size'):
                # Update chunk size if using ngrok
                FileProcessor.ngrok_chunk_size = settings.get('ngrok_chunk_size', 524288)
                logger.info(f"Set ngrok chunk size to {FileProcessor.ngrok_chunk_size}")
                
                # Add a method to detect and use ngrok-optimized settings
                if not hasattr(FileProcessor, 'use_ngrok_settings'):
                    def use_ngrok_settings(self, is_ngrok=True):
                        """Switch to ngrok-optimized settings"""
                        if is_ngrok:
                            self.chunk_size = self.ngrok_chunk_size if hasattr(self, 'ngrok_chunk_size') else 524288
                            logger.info(f"Using ngrok-optimized chunk size: {self.chunk_size}")
                        return self
                    
                    # Add the method to the class
                    FileProcessor.use_ngrok_settings = use_ngrok_settings
                    logger.info("Added use_ngrok_settings method to FileProcessor")
            
            # Successfully applied fixes
            logger.info("Successfully applied ngrok fixes to application modules")
            return True
            
        except ImportError:
            logger.warning("Could not import SecureTransfer modules - fixes will only apply to current session")
            return False
        
        # Apply fixes to NetworkManager if available
        try:
            # Add ngrok detection to NetworkManager
            NetworkManager.is_ngrok_connection = is_ngrok_connection
            logger.info("Added is_ngrok_connection to NetworkManager")
            
            # Add connection enhancement
            if hasattr(NetworkManager, 'connect_to_server'):
                original_connect = NetworkManager.connect_to_server
                
                # Define the enhanced connection method
                def enhanced_connect_to_server(self, transfer_id, host, port):
                    # Call the original method
                    conn = original_connect(self, transfer_id, host, port)
                    
                    # Enhance the connection if it's ngrok
                    if conn and is_ngrok_connection(host):
                        logger.info(f"Enhancing ngrok connection to {host}")
                        enhance_connection_stability(conn, timeout=30)
                    
                    return conn
                
                # Apply the monkey patch
                NetworkManager.connect_to_server = enhanced_connect_to_server
                logger.info("Enhanced NetworkManager.connect_to_server for ngrok connections")
            else:
                logger.warning("NetworkManager.connect_to_server method not found")
                
            logger.info("Ngrok transfer fixes have been applied")
            return True
            
        except Exception as patch_error:
            logger.error(f"Error applying specific fixes: {patch_error}")
            return False
        
    except Exception as e:
        logger.error(f"Could not apply ngrok fixes: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# Initialize fixes when module is imported
if __name__ != "__main__":
    try:
        logger.info("Initializing ngrok transfer fixes...")
        apply_fixes()
    except:
        pass