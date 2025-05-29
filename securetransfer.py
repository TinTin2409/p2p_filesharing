"""
SecureTransfer - Main Application
The entry point for the SecureTransfer application
"""

import os
import sys
import tkinter as tk
from securetransfer.ui.login_window import LoginWindow
from securetransfer.ui.main_window import MainWindow


def setup_environment():
    """Set up the application environment"""
    # Create necessary directories
    os.makedirs(os.path.join("securetransfer", "data", "users"), exist_ok=True)
    os.makedirs(os.path.join("securetransfer", "data", "transfers"), exist_ok=True)
    os.makedirs(os.path.join("securetransfer", "data", "downloads"), exist_ok=True)
    os.makedirs(os.path.join("securetransfer", "data", "temp"), exist_ok=True)


def on_login_success(username, encryption_manager):
    """Callback for successful login"""
    # Start the main application window
    app = MainWindow(username, encryption_manager)
    app.run()


def initialize_ngrok_fixes():
    """Initialize the ngrok transfer fixes module"""
    try:
        print("Initializing ngrok transfer fixes...")
        import ngrok_transfer_fix
        # Apply the fixes to optimize for ngrok transfers
        ngrok_transfer_fix.optimize_for_ngrok()
        # Apply fixes to application modules
        ngrok_transfer_fix.apply_fixes()
        print("Ngrok transfer fixes loaded successfully")
        return True
    except ImportError:
        print("Warning: Could not load ngrok_transfer_fix module")
        return False
    except Exception as e:
        print(f"Error initializing ngrok fixes: {e}")
        return False


def main():
    """Application entry point"""
    try:
        # Set up the environment
        print("Setting up environment...")
        setup_environment()
        
        # Initialize ngrok fixes
        initialize_ngrok_fixes()
        
        # Start with the login window
        print("Creating login window...")
        login = LoginWindow(on_login_success)
        print("Starting login window...")
        login.run()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        import time
        time.sleep(10)  # Keep console window open for 10 seconds to see error


if __name__ == "__main__":
    main()
