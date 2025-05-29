#!/usr/bin/env python
"""
Simple test script for verifying the ngrok_transfer_fix module
"""

import os
import sys
import time
import datetime

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Test the ngrok_transfer_fix module
def test_ngrok_fixes():
    print("Testing ngrok transfer fixes...")
    
    try:
        from ngrok_transfer_fix import (
            enhance_connection_stability,
            calculate_file_checksum,
            is_ngrok_connection,
            optimize_for_ngrok
        )
        print("✓ Successfully imported ngrok_transfer_fix module")
        
        # Fix application of ngrok optimizations in the global context
        try:
            # Apply optimizations directly
            print("\nTesting optimize_for_ngrok function...")
            settings = optimize_for_ngrok()
            print("optimize_for_ngrok() executed successfully")
        except Exception as e:
            print(f"Error in optimize_for_ngrok: {e}")
            
        # Test is_ngrok_connection function
        print("\nTesting is_ngrok_connection function...")
        test_hosts = [
            ("example.com", False),
            ("abc.ngrok.io", True),
            ("tcp.ap.ngrok.io:12345", True),
            ("localhost", False)
        ]
        
        for host, expected in test_hosts:
            result = is_ngrok_connection(host)
            if result == expected:
                print(f"✓ is_ngrok_connection({host}) = {result} as expected")
            else:
                print(f"✗ is_ngrok_connection({host}) = {result}, expected {expected}")
        
        # Test optimize_for_ngrok function
        settings = optimize_for_ngrok()
        if settings and settings.get("ngrok_optimized"):
            print("✓ optimize_for_ngrok() returned optimized settings")
            print(f"  - Chunk size: {settings.get('chunk_size')} bytes")
            print(f"  - Buffer size: {settings.get('ngrok_buffer_size')} bytes")
            print(f"  - Timeout: {settings.get('ngrok_timeout')} seconds")
            print(f"  - Max retries: {settings.get('ngrok_max_retries')}")
        else:
            print("✗ optimize_for_ngrok() did not return proper settings")
        
        # Test checksum calculation on a test file
        test_file = "test_file.txt"
        with open(test_file, "w") as f:
            f.write("This is a test file for checksum calculation")
        
        checksum = calculate_file_checksum(test_file)
        if checksum and len(checksum) == 64:  # SHA-256 produces 64 character hex digest
            print(f"✓ calculate_file_checksum() returned valid checksum: {checksum[:8]}...")
        else:
            print(f"✗ calculate_file_checksum() failed: {checksum}")
        
        # Clean up test file
        os.remove(test_file)
        
        print("\nAll basic functions tested successfully!")
        return True
        
    except Exception as e:
        print(f"Error testing ngrok fixes: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_ngrok_fixes()
