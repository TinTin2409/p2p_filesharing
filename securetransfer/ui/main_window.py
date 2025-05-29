"""
SecureTransfer - Main Window
Implements the main application UI with modern styling
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import uuid

# Import internal modules
from ..core.digital_signature import DigitalSignature, SignatureAlgorithm
from ..core.file_processor import FileProcessor
from ..networking.connection import NetworkManager, ConnectionType, TransferStatus
from ..data.database import DatabaseManager
from ..ui.settings_dialog import SettingsDialog
from ..ui.help_dialogs import UserGuideDialog, AboutDialog


# Color scheme (same as login window)
COLORS = {
    "primary": "#2c3e50",      # Dark blue
    "secondary": "#34495e",    # Slightly lighter blue
    "accent": "#3498db",       # Bright blue
    "success": "#2ecc71",      # Green
    "warning": "#f39c12",      # Orange
    "danger": "#e74c3c",       # Red
    "light": "#ecf0f1",        # Off-white
    "muted": "#bdc3c7"         # Light gray
}

# Try to import the ngrok_transfer_fix module
try:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from ngrok_transfer_fix import is_ngrok_connection, optimize_for_ngrok
    NGROK_FIX_AVAILABLE = True
except ImportError:
    NGROK_FIX_AVAILABLE = False


class MainWindow:
    """Modern main window with file transfer functionality"""
    
    def __init__(self, username, encryption_manager):
        """Initialize with user info and encryption manager"""
        self.username = username
        self.encryption_manager = encryption_manager
          # Initialize components
        self.digital_signature = DigitalSignature(
            private_key=encryption_manager.private_key,
            public_key=encryption_manager.public_key
        )
        
        # Initialize database manager and load settings
        self.db_manager = DatabaseManager()
        self.settings = self.db_manager.get_settings()
        self.db_manager.startup_cleanup()
        
        # Set chunk size from settings
        chunk_size = self.settings.get("chunk_size", 2*1024*1024)
        
        # Create file processor with settings
        self.file_processor = FileProcessor(
            digital_signature=self.digital_signature,
            encryption_manager=self.encryption_manager,
            chunk_size=chunk_size
        )
        self.network_manager = NetworkManager()
        
        # Set up callbacks
        self.file_processor.set_progress_callback(self.update_progress)
        self.network_manager.set_status_callback(self.update_transfer_status)
          # UI elements to be set up later
        self.root = None
        self.status_var = None
        self.progress_var = None
        self.progress_bar = None
        self.log_text = None
        
        # Transfer tracking
        self.active_transfers = {}
        self.full_file_path = None  # Store the full path of selected file
        
        # Create the UI
        self.create_ui()
        
        # Start periodic cleanup timer (every 6 hours)
        self.schedule_periodic_cleanup()
    
    def create_ui(self):
        """Create the main application UI"""
        self.root = tk.Tk()
        self.root.title("SecureTransfer")
        self.root.geometry("800x600")
        self.root.configure(bg=COLORS["primary"])
        
        # Create the menu
        self.create_menu()
        
        # Main content area
        content_frame = tk.Frame(self.root, bg=COLORS["secondary"])
        content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Header with user info
        header_frame = tk.Frame(content_frame, bg=COLORS["secondary"], height=50)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title = tk.Label(header_frame, text="SecureTransfer", font=("Helvetica", 18, "bold"),
                       fg=COLORS["light"], bg=COLORS["secondary"])
        title.pack(side=tk.LEFT)
        
        user_info = tk.Label(header_frame, text=f"Logged in as {self.username}",
                          font=("Helvetica", 10), fg=COLORS["muted"], bg=COLORS["secondary"])
        user_info.pack(side=tk.RIGHT)
        
        # Create tabs
        self.tab_control = ttk.Notebook(content_frame)
        
        self.send_tab = tk.Frame(self.tab_control, bg=COLORS["secondary"])
        self.receive_tab = tk.Frame(self.tab_control, bg=COLORS["secondary"])
        self.history_tab = tk.Frame(self.tab_control, bg=COLORS["secondary"])
        
        self.tab_control.add(self.send_tab, text="Send Files")
        self.tab_control.add(self.receive_tab, text="Receive Files")
        self.tab_control.add(self.history_tab, text="Transfer History")
        
        self.tab_control.pack(expand=True, fill=tk.BOTH)
        
        # Set up each tab
        self.setup_send_tab()
        self.setup_receive_tab()
        self.setup_history_tab()
        
        # Status bar at the bottom
        status_frame = tk.Frame(self.root, bg=COLORS["secondary"], height=30)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = tk.Label(status_frame, textvariable=self.status_var,
                              font=("Helvetica", 9), fg=COLORS["light"], bg=COLORS["secondary"],
                              anchor=tk.W, padx=10, pady=5)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def create_menu(self):
        """Create the application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        filemenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Send Files", command=lambda: self.tab_control.select(0))
        filemenu.add_command(label="Receive Files", command=lambda: self.tab_control.select(1))
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        
        # Options menu
        optionsmenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Options", menu=optionsmenu)
        optionsmenu.add_command(label="Settings", command=self.open_settings)
        
        # Help menu
        helpmenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=helpmenu)
        helpmenu.add_command(label="User Guide", command=self.show_user_guide)
        helpmenu.add_command(label="About", command=self.show_about)
    
    def setup_send_tab(self):
        """Set up the Send Files tab"""
        # Left panel for file selection
        left_panel = tk.Frame(self.send_tab, bg=COLORS["secondary"], width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10, expand=False)
        
        # Right panel for connection info
        right_panel = tk.Frame(self.send_tab, bg=COLORS["secondary"])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        # File selection area
        file_frame = tk.LabelFrame(left_panel, text="Select File", fg=COLORS["light"],
                                 bg=COLORS["secondary"], font=("Helvetica", 10))
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.selected_file_var = tk.StringVar(value="No file selected")
        selected_file_label = tk.Label(file_frame, textvariable=self.selected_file_var,
                                    wraplength=280, fg=COLORS["muted"], bg=COLORS["secondary"])
        selected_file_label.pack(fill=tk.X, padx=10, pady=(10, 5))
        browse_button = tk.Button(file_frame, text="Browse", command=self.select_send_file,
                               bg=COLORS["accent"], fg=COLORS["light"],
                               activebackground=COLORS["accent"], activeforeground=COLORS["light"],
                               relief=tk.FLAT, padx=10, pady=5)
        browse_button.pack(pady=(0, 10))
        
        # Encryption status
        encryption_frame = tk.LabelFrame(left_panel, text="Encryption Status", fg=COLORS["light"],
                                       bg=COLORS["secondary"], font=("Helvetica", 10))
        encryption_frame.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        # Check if encryption is available (RSA keys properly loaded)
        encryption_status = "Enabled" if hasattr(self.encryption_manager, 'rsa_public_key') and self.encryption_manager.rsa_public_key else "Disabled"
        encryption_color = COLORS["success"] if encryption_status == "Enabled" else COLORS["danger"]
        
        status_label = tk.Label(encryption_frame, text=f"Status: ", 
                                fg=COLORS["light"], bg=COLORS["secondary"])
        status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        encryption_status_label = tk.Label(encryption_frame, text=encryption_status, 
                                         fg=encryption_color, bg=COLORS["secondary"],
                                         font=("Helvetica", 10, "bold"))
        encryption_status_label.pack(side=tk.LEFT, pady=5)
        
        # Connection options
        connection_frame = tk.LabelFrame(left_panel, text="Connection", fg=COLORS["light"],
                                       bg=COLORS["secondary"], font=("Helvetica", 10))
        connection_frame.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        self.connection_type_var = tk.StringVar(value=ConnectionType.LOCAL)
        
        # Radio buttons for connection type
        local_radio = tk.Radiobutton(connection_frame, text="Local Network", 
                                   variable=self.connection_type_var, value=ConnectionType.LOCAL,
                                   fg=COLORS["light"], bg=COLORS["secondary"],
                                   selectcolor=COLORS["secondary"], activebackground=COLORS["secondary"])
        local_radio.pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        direct_radio = tk.Radiobutton(connection_frame, text="Direct Connection", 
                                    variable=self.connection_type_var, value=ConnectionType.DIRECT,
                                    fg=COLORS["light"], bg=COLORS["secondary"],
                                    selectcolor=COLORS["secondary"], activebackground=COLORS["secondary"])
        direct_radio.pack(anchor=tk.W, padx=10)
        
        ngrok_radio = tk.Radiobutton(connection_frame, text="Ngrok Tunnel", 
                                   variable=self.connection_type_var, value=ConnectionType.NGROK,
                                   fg=COLORS["light"], bg=COLORS["secondary"],
                                   selectcolor=COLORS["secondary"], activebackground=COLORS["secondary"])
        ngrok_radio.pack(anchor=tk.W, padx=10, pady=(0, 5))
        
        # Port selection
        port_frame = tk.Frame(connection_frame, bg=COLORS["secondary"])
        port_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(port_frame, text="Port:", fg=COLORS["light"], bg=COLORS["secondary"]).pack(side=tk.LEFT)
        
        self.port_var = tk.StringVar(value="5000")
        port_entry = tk.Entry(port_frame, textvariable=self.port_var, width=6)
        port_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Start button
        start_button = tk.Button(left_panel, text="Start Transfer", command=self.start_send_transfer,
                              bg=COLORS["success"], fg=COLORS["light"],
                              activebackground=COLORS["success"], activeforeground=COLORS["light"],
                              font=("Helvetica", 10, "bold"),
                              relief=tk.FLAT, padx=10, pady=8)
        start_button.pack(fill=tk.X, padx=5, pady=10)
        
        # Connection info area (right panel)
        info_frame = tk.LabelFrame(right_panel, text="Connection Information", fg=COLORS["light"],
                                 bg=COLORS["secondary"], font=("Helvetica", 10))
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Connection details
        self.local_ip_var = tk.StringVar(value=f"Local IP: {self.network_manager.local_ip}")
        local_ip_label = tk.Label(info_frame, textvariable=self.local_ip_var,
                               fg=COLORS["light"], bg=COLORS["secondary"])
        local_ip_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.public_url_var = tk.StringVar(value="Public URL: Not available")
        public_url_label = tk.Label(info_frame, textvariable=self.public_url_var,
                                 fg=COLORS["light"], bg=COLORS["secondary"])
        public_url_label.pack(anchor=tk.W, padx=10, pady=(0, 5))
          # Public key display
        key_frame = tk.LabelFrame(right_panel, text="Your RSA Public Key (for encryption)", fg=COLORS["light"],
                                bg=COLORS["secondary"], font=("Helvetica", 10))
        key_frame.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        # Add info label
        info_label = tk.Label(key_frame, text="Share this RSA key with recipients so they can decrypt your files.\nFiles are automatically signed with your EC key for verification.", 
                             fg=COLORS["muted"], bg=COLORS["secondary"], font=("Helvetica", 8),
                             wraplength=300, justify=tk.LEFT)
        info_label.pack(fill=tk.X, padx=10, pady=(5, 0))
          # Get RSA public key in PEM format (for encryption)
        from ..core.encryption_manager import public_encode_to_string, rsa_public_encode_to_string
        
        # Use RSA public key since we're sharing this for encryption
        try:
            public_key_pem = rsa_public_encode_to_string(self.encryption_manager.rsa_public_key)
        except (TypeError, AttributeError):
            # Fallback to EC public key if RSA not available
            public_key_pem = public_encode_to_string(self.encryption_manager.public_key)
            print("Warning: Using EC public key as fallback, but this won't work for encryption")
        
        # Show only the first part and add copy button
        key_display = tk.Text(key_frame, height=6, width=40, wrap=tk.WORD, bg=COLORS["primary"], fg=COLORS["light"])
        key_display.pack(fill=tk.X, padx=10, pady=10)
        key_display.insert(tk.END, public_key_pem)
        key_display.config(state=tk.DISABLED)
        
        copy_button = tk.Button(key_frame, text="Copy RSA Key to Clipboard", 
                             command=lambda: self.copy_to_clipboard(public_key_pem),
                             bg=COLORS["accent"], fg=COLORS["light"],
                             activebackground=COLORS["accent"], activeforeground=COLORS["light"],
                             relief=tk.FLAT, padx=10, pady=2)
        copy_button.pack(pady=(0, 10))
        
        # Log area
        log_frame = tk.LabelFrame(right_panel, text="Transfer Log", fg=COLORS["light"],
                               bg=COLORS["secondary"], font=("Helvetica", 10))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(10, 5))
        
        # Scrolled text widget for logs
        self.send_log = tk.Text(log_frame, height=10, bg=COLORS["primary"], fg=COLORS["light"])
        log_scrollbar = tk.Scrollbar(log_frame, command=self.send_log.yview)
        self.send_log.configure(yscrollcommand=log_scrollbar.set)
        
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.send_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Progress bar
        progress_frame = tk.Frame(right_panel, bg=COLORS["secondary"])
        progress_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.send_progress_var = tk.DoubleVar(value=0)
        self.send_progress_bar = ttk.Progressbar(progress_frame, variable=self.send_progress_var,
                                              orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.send_progress_bar.pack(fill=tk.X, padx=5, pady=5)
    
    def setup_receive_tab(self):
        """Set up the Receive Files tab"""
        # Left panel for connection details
        left_panel = tk.Frame(self.receive_tab, bg=COLORS["secondary"], width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10, expand=False)
        
        # Right panel for file information
        right_panel = tk.Frame(self.receive_tab, bg=COLORS["secondary"])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        # Connection details form
        conn_frame = tk.LabelFrame(left_panel, text="Connection Details", fg=COLORS["light"],
                                 bg=COLORS["secondary"], font=("Helvetica", 10))
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Host input
        host_frame = tk.Frame(conn_frame, bg=COLORS["secondary"])
        host_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        tk.Label(host_frame, text="Host:", width=8, anchor=tk.W,
              fg=COLORS["light"], bg=COLORS["secondary"]).pack(side=tk.LEFT)
        
        self.host_var = tk.StringVar()
        host_entry = tk.Entry(host_frame, textvariable=self.host_var)
        host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Port input
        port_frame = tk.Frame(conn_frame, bg=COLORS["secondary"])
        port_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        tk.Label(port_frame, text="Port:", width=8, anchor=tk.W,
              fg=COLORS["light"], bg=COLORS["secondary"]).pack(side=tk.LEFT)
        
        self.receive_port_var = tk.StringVar(value="5000")
        port_entry = tk.Entry(port_frame, textvariable=self.receive_port_var, width=6)
        port_entry.pack(side=tk.LEFT)
          # Sender's RSA public key (for decryption)
        key_frame = tk.LabelFrame(left_panel, text="Sender's RSA Public Key (for decryption)", fg=COLORS["light"],
                                bg=COLORS["secondary"], font=("Helvetica", 10))
        key_frame.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        # Add info label
        info_label = tk.Label(key_frame, text="Paste the sender's RSA public key to decrypt received files.\nSignatures are verified automatically.", 
                             fg=COLORS["muted"], bg=COLORS["secondary"], font=("Helvetica", 8),
                             wraplength=300, justify=tk.LEFT)
        info_label.pack(fill=tk.X, padx=10, pady=(5, 0))
        
        self.sender_key_text = tk.Text(key_frame, height=6, width=40, bg=COLORS["primary"], fg=COLORS["light"])
        self.sender_key_text.pack(fill=tk.X, padx=10, pady=10)
        
        paste_button = tk.Button(key_frame, text="Paste RSA Key from Clipboard", 
                              command=self.paste_from_clipboard,
                              bg=COLORS["accent"], fg=COLORS["light"],
                              activebackground=COLORS["accent"], activeforeground=COLORS["light"],
                              relief=tk.FLAT, padx=10, pady=2)
        paste_button.pack(pady=(0, 10))
        
        # Connect button
        connect_button = tk.Button(left_panel, text="Connect and Receive", command=self.start_receive_transfer,
                                bg=COLORS["success"], fg=COLORS["light"],
                                activebackground=COLORS["success"], activeforeground=COLORS["light"],
                                font=("Helvetica", 10, "bold"),
                                relief=tk.FLAT, padx=10, pady=8)
        connect_button.pack(fill=tk.X, padx=5, pady=10)
        
        # Log area (right panel)
        log_frame = tk.LabelFrame(right_panel, text="Transfer Log", fg=COLORS["light"],
                               bg=COLORS["secondary"], font=("Helvetica", 10))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrolled text widget for logs
        self.receive_log = tk.Text(log_frame, height=10, bg=COLORS["primary"], fg=COLORS["light"])
        log_scrollbar = tk.Scrollbar(log_frame, command=self.receive_log.yview)
        self.receive_log.configure(yscrollcommand=log_scrollbar.set)
        
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.receive_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Progress bar
        progress_frame = tk.Frame(right_panel, bg=COLORS["secondary"])
        progress_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.receive_progress_var = tk.DoubleVar(value=0)
        self.receive_progress_bar = ttk.Progressbar(progress_frame, variable=self.receive_progress_var,
                                                 orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.receive_progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # Save location
        save_frame = tk.Frame(right_panel, bg=COLORS["secondary"])
        save_frame.pack(fill=tk.X, padx=5, pady=(0, 10))
        
        tk.Label(save_frame, text="Save Location:", fg=COLORS["light"], bg=COLORS["secondary"]).pack(side=tk.LEFT, padx=5)
        
        self.save_location_var = tk.StringVar(value=os.path.join("securetransfer", "data", "downloads"))
        save_location_entry = tk.Entry(save_frame, textvariable=self.save_location_var, width=30)
        save_location_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        browse_button = tk.Button(save_frame, text="Browse", 
                               command=self.select_save_location,
                               bg=COLORS["accent"], fg=COLORS["light"],
                               activebackground=COLORS["accent"], activeforeground=COLORS["light"],
                               relief=tk.FLAT, padx=5, pady=2)
        browse_button.pack(side=tk.RIGHT, padx=5)
    
    def setup_history_tab(self):
        """Set up the Transfer History tab"""
        # Create the tree view for transfer history
        columns = ("timestamp", "type", "filename", "size", "status")
        self.history_tree = ttk.Treeview(self.history_tab, columns=columns, show="headings")
        
        # Configure column headings
        self.history_tree.heading("timestamp", text="Date & Time")
        self.history_tree.heading("type", text="Type")
        self.history_tree.heading("filename", text="Filename")
        self.history_tree.heading("size", text="Size")
        self.history_tree.heading("status", text="Status")
        
        # Configure column widths
        self.history_tree.column("timestamp", width=150)
        self.history_tree.column("type", width=80)
        self.history_tree.column("filename", width=250)
        self.history_tree.column("size", width=80)
        self.history_tree.column("status", width=100)
          # Add a scrollbar
        scrollbar = ttk.Scrollbar(self.history_tab, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the widgets
        scrollbar.pack(side="right", fill="y")
        self.history_tree.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Load transfer history data
        self.load_transfer_history()
    
    def select_send_file(self):
        """Open file dialog to select a file to send"""
        file_path = filedialog.askopenfilename(title="Select File to Send")
        if file_path:
            filename = os.path.basename(file_path)
            self.full_file_path = file_path  # Store the full path
            self.selected_file_var.set(filename)
            self.log_to_send(f"Selected file: {filename}")
    
    def select_save_location(self):
        """Open directory dialog to select save location"""
        directory = filedialog.askdirectory(title="Select Save Location")
        if directory:
            self.save_location_var.set(directory)
            
    def start_send_transfer(self):
        """Start the file sending process"""
        if not hasattr(self, 'full_file_path') or not self.full_file_path:
            messagebox.showwarning("No File", "Please select a file to send")
            return
        
        file_path = self.full_file_path  # Use the full file path instead of just filename
            
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Please enter a valid port number")
            return
            
        connection_type = self.connection_type_var.get()
        
        # Check if using ngrok and show recommendations
        if connection_type == ConnectionType.NGROK:
            # Show ngrok-specific recommendations
            if NGROK_FIX_AVAILABLE:
                optimize_settings = messagebox.askyesno(
                    "Ngrok Transfer Settings", 
                    "Ngrok transfers require special settings for optimal reliability.\n\n"
                    "Do you want to optimize settings for this transfer?\n\n"
                    "(Recommended for encrypted files over 10MB)"
                )
                if optimize_settings:
                    self.log_to_send("Applying ngrok transfer optimizations...")
                    try:
                        optimize_for_ngrok()
                        self.log_to_send("Ngrok optimizations applied successfully")
                    except Exception as e:
                        self.log_to_send(f"Could not apply optimizations: {e}")
            else:
                messagebox.showinfo(
                    "Ngrok Transfer", 
                    "For best results with ngrok transfers:\n"
                    "- Use smaller chunks (512KB recommended)\n"
                    "- Avoid transferring files larger than 100MB\n"
                    "- Ensure both parties have stable connections"
                )
        
        # Generate transfer ID
        transfer_id = str(uuid.uuid4())
        
        # Log the start
        self.log_to_send(f"Starting transfer with ID: {transfer_id}")
        self.log_to_send(f"Connection type: {connection_type}")
        
        # Start the transfer in a separate thread
        threading.Thread(
            target=self._send_file_thread,
            args=(transfer_id, file_path, port, connection_type),
            daemon=True
        ).start()
    def _send_file_thread(self, transfer_id, file_path, port, connection_type):
        """Thread to handle the file sending process"""
        try:
            # Prepare the file for transfer
            self.log_to_send("Preparing file for transfer...")
            self.file_processor.set_progress_callback(
                lambda current, total, msg: self.update_send_progress(current, total, msg)
            )
            
            # Get settings for encryption
            self.settings = self.db_manager.get_settings()
            
            # Set chunk size from settings
            chunk_size = self.settings.get("chunk_size", 2*1024*1024)
            self.file_processor.chunk_size = chunk_size
            
            # Apply security settings
            encryption_strength = self.settings.get("encryption_strength", "SECP384R1")
            signature_algorithm = self.settings.get("signature_algorithm", "SHA256")            # Import the RSA module for type checking
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            # For simplicity in this implementation, we'll encrypt using our own RSA public key
            # In a complete implementation, you'd use the recipient's RSA public key
            recipient_public_key = self.encryption_manager.rsa_public_key
            
            if not isinstance(recipient_public_key, rsa.RSAPublicKey):
                self.log_to_send("Warning: RSA public key not available, encryption may fail")
              # Log security settings
            self.log_to_send(f"Using chunk size: {chunk_size/1024/1024:.1f} MB")
            self.log_to_send(f"Using encryption strength: {encryption_strength}")
            self.log_to_send(f"Using signature algorithm: {signature_algorithm}")
              # Check if encryption is available
            if recipient_public_key and hasattr(recipient_public_key, 'encrypt'):
                self.log_to_send("File encryption: ENABLED (using RSA key)")
                
                # Check the key type more specifically
                from cryptography.hazmat.primitives.asymmetric import rsa
                if isinstance(recipient_public_key, rsa.RSAPublicKey):
                    key_size = recipient_public_key.key_size
                    self.log_to_send(f"Using {key_size}-bit RSA key for encryption")
                else:
                    self.log_to_send("Warning: Non-RSA key being used, encryption may fail")
            else:
                self.log_to_send("Warning: File encryption DISABLED - valid RSA key not available")
                
            # Split and encrypt the file
            transfer_id = self.file_processor.split_file(file_path, recipient_public_key)
            
            # Get the path to the prepared package
            transfer_dir = os.path.join("securetransfer", "data", "transfers", transfer_id)
            package_path = os.path.join(transfer_dir, f"{transfer_id}.zip")
                                      # Start the server for file transfer
            self.log_to_send(f"Starting server on port {port} using {connection_type}...")
            server_info = self.network_manager.start_server(
                transfer_id, port, connection_type
            )
              # Debug output and direct UI update
            public_address = server_info.get('public_address', 'Not available')
            self.log_to_send(f"DEBUG: Public address from server: {public_address}")
            
            # Force UI update immediately with public address
            if public_address and public_address != "Not available":
                self.public_url_var.set(f"Public URL: {public_address}")
                self.root.update()
            
            # Add a note for HTTP/HTTPS URLs to help users
            if public_address and (public_address.startswith('http://') or public_address.startswith('https://')):
                # Extract just the hostname for easier copying
                public_url_text = f"Public URL: {public_address}"
                # Update UI immediately
                self.public_url_var.set(public_url_text)
                self.log_to_send("NOTE: When receiving, enter just the hostname without http:// or https://")
                self.log_to_send(f"HOSTNAME: {public_address.split('//')[1].split(':')[0]}")
            elif public_address and public_address.startswith("Ngrok Error:"):
                # Show a more helpful error message for Ngrok errors
                error_msg = public_address.replace("Ngrok Error: ", "")
                public_url_text = f"Public URL: Not available (Ngrok error)"
                # Update UI immediately
                self.public_url_var.set(public_url_text)
                self.log_to_send(f"NGROK ERROR: {error_msg}")
                self.log_to_send("SOLUTION: Make sure your Ngrok token is valid and up to date.")
                self.log_to_send("Run ngrok_setup.py to configure a new token.")
            elif public_address == "Not available":
                public_url_text = "Public URL: Not available"
                # Update UI immediately
                self.public_url_var.set(public_url_text)
                if connection_type == ConnectionType.NGROK:
                    self.log_to_send("WARNING: Ngrok public URL could not be obtained.")
                    self.log_to_send("SOLUTION: Check your internet connection and Ngrok configuration.")
            else:
                public_url_text = f"Public URL: {public_address}"
                # Update UI immediately
                self.public_url_var.set(public_url_text)
                
            # Force UI to update
            self.root.update()
            
            # Wait for a client to connect
            self.log_to_send("Waiting for receiver to connect...")
            conn = self.network_manager.accept_connection(transfer_id)
            
            if conn:
                # Send the file
                self.log_to_send("Connection established. Sending file...")
                self.network_manager.send_file(conn, transfer_id, package_path)
                
                # Clean up
                self.log_to_send("Transfer complete!")
                conn.close()
            else:
                self.log_to_send("Connection failed or timed out")
                
            # Stop the server
            self.network_manager.stop_server(transfer_id)
            
            # Add to history
            self._add_to_history(transfer_id, "send", file_path, TransferStatus.COMPLETE)
            
        except Exception as e:
            self.log_to_send(f"Error during transfer: {e}")
            self._add_to_history(transfer_id, "send", file_path, TransferStatus.FAILED)
    
    def start_receive_transfer(self):
        """Start the file receiving process"""
        host = self.host_var.get().strip()
        if not host:
            messagebox.showwarning("Missing Host", "Please enter the host address")
            return
            
        try:
            port = int(self.receive_port_var.get())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Please enter a valid port number")
            return
            
        # Get sender's public key
        sender_key_pem = self.sender_key_text.get("1.0", tk.END).strip()
        if not sender_key_pem:
            messagebox.showwarning("Missing Key", "Please enter the sender's public key")
            return
            
        # Generate transfer ID
        transfer_id = str(uuid.uuid4())
        
        # Get save location
        save_location = self.save_location_var.get()
        os.makedirs(save_location, exist_ok=True)
        
        # Log the start
        self.log_to_receive(f"Starting transfer with ID: {transfer_id}")
        self.log_to_receive(f"Connecting to {host}:{port}")
          # Start the transfer in a separate thread
        threading.Thread(
            target=self._receive_file_thread,
            args=(transfer_id, host, port, sender_key_pem, save_location),
            daemon=True
        ).start()
    
    def _receive_file_thread(self, transfer_id, host, port, sender_key_pem, save_location):
        """Thread to handle the file receiving process"""
        try:
            # Clean up the host input if it contains http:// or https://
            if host.startswith("http://") or host.startswith("https://"):
                self.log_to_receive("Detected URL format. Extracting hostname...")
                import urllib.parse
                parsed_url = urllib.parse.urlparse(host)
                
                # For Ngrok URLs, make sure we're not losing any subdomain parts
                # Ngrok URLs have format: https://xxxx-xx-xxx-xxx-xxx.ngrok-free.app
                self.log_to_receive(f"Original URL: {host}")
                
                # Extract just the hostname without any port that might be included
                host = parsed_url.netloc.split(':')[0]
                self.log_to_receive(f"Using hostname: {host}")
                
                # For Ngrok tunnels, use the protocol's standard port
                # This is critical because Ngrok free accounts require using their HTTP/HTTPS ports
                if not port or port == 0:
                    port = 443 if parsed_url.scheme == "https" else 80
                    self.log_to_receive(f"Using standard {parsed_url.scheme.upper()} port: {port}")
            
            self.log_to_receive(f"Attempting to connect to {host}:{port}...")
            # Connect to the sender
            conn = self.network_manager.connect_to_server(transfer_id, host, port)
            
            if conn:                # Receive the file
                self.log_to_receive("Connected. Receiving file...")
                temp_dir = os.path.join("securetransfer", "data", "temp")
                os.makedirs(temp_dir, exist_ok=True)
                
                received_path = self.network_manager.receive_file(conn, transfer_id, temp_dir)
                
                if received_path:
                    self.log_to_receive(f"File received: {os.path.basename(received_path)}")
                    # Extract and process the file
                    self.log_to_receive("Verifying and extracting file...")
                    
                    # Unzip the package
                    extract_dir = os.path.join(temp_dir, transfer_id)
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    self.file_processor.extract_zip(received_path, extract_dir)
                    
                    # Configure the digital signature and decryption with sender's keys
                    try:
                        from ..core.encryption_manager import rsa_public_decode_from_string
                        from cryptography.hazmat.primitives.asymmetric import rsa
                        
                        # Validate and load the RSA key for decryption
                        key, key_type = self.encryption_manager.parse_pem_key(sender_key_pem)
                        
                        if key_type == "rsa":
                            try:
                                sender_rsa_key = rsa_public_decode_from_string(sender_key_pem)
                                self.log_to_receive("✓ RSA public key loaded successfully")
                                self.log_to_receive("Ready to decrypt files encrypted with this key")
                                # Store in encryption manager for decryption
                                self.file_processor.encryption_manager.recipient_key = sender_rsa_key
                            except Exception as e:
                                self.log_to_receive(f"✗ Failed to load RSA key: {e}")
                                self.log_to_receive("Decryption will fail if the file is encrypted")
                        else:
                            self.log_to_receive("⚠️ Warning: No valid RSA key provided")
                            self.log_to_receive("Decryption will fail if the file is encrypted")
                            self.log_to_receive("Please ensure you have the sender's RSA public key")

                        # For signature verification, we'll use the sender's EC key embedded in the file
                        # No need for manual EC key input - signatures are verified automatically
                        self.log_to_receive("Signature verification will be performed automatically using embedded keys")
                          # Set the encryption settings from database
                        self.settings = self.db_manager.get_settings()
                        chunk_size = self.settings.get("chunk_size", 2*1024*1024)
                        self.file_processor.chunk_size = chunk_size
                        
                        self.log_to_receive(f"Using chunk size: {chunk_size/1024/1024:.1f} MB")
                        self.log_to_receive("Processing received files...")
                    except Exception as e:
                        self.log_to_receive(f"Warning: Could not parse sender's public key: {e}")
                    
                    # Merge the chunks and verify
                    self.file_processor.set_progress_callback(
                        lambda current, total, msg: self.update_receive_progress(current, total, msg)
                    )
                    
                    final_path = self.file_processor.merge_chunks(extract_dir, save_location)
                    
                    # Clean up temp files after successful extraction
                    temp_filename = os.path.basename(received_path)
                    from ..data.database import DatabaseManager
                    db_manager = DatabaseManager()
                    db_manager.cleanup_after_extraction(transfer_id, temp_filename)
                    
                    # Report success
                    self.log_to_receive(f"File saved to: {final_path}")
                    self.log_to_receive("Transfer complete!")
                    
                    # Add to history
                    self._add_to_history(transfer_id, "receive", final_path, TransferStatus.COMPLETE)
                    
                else:
                    self.log_to_receive("Error: File reception failed")
                    self._add_to_history(transfer_id, "receive", "unknown", TransferStatus.FAILED)
                
                # Close the connection
                conn.close()
                
            else:
                self.log_to_receive("Error: Could not connect to sender")
                self._add_to_history(transfer_id, "receive", "unknown", TransferStatus.FAILED)
                
        except Exception as e:
            self.log_to_receive(f"Error during transfer: {e}")
            self._add_to_history(transfer_id, "receive", "unknown", TransferStatus.FAILED)
    
    def update_send_progress(self, current, total, message=None):
        """Update the progress bar in the Send tab"""
        progress = min(100, int(current * 100 / max(1, total)))
        
        # Use root.after to safely update UI from a non-main thread
        self.root.after(0, lambda: self.send_progress_var.set(progress))
        
        if message:
            self.log_to_send(message)
    
    def update_receive_progress(self, current, total, message=None):
        """Update the progress bar in the Receive tab"""
        progress = min(100, int(current * 100 / max(1, total)))
        
        # Use root.after to safely update UI from a non-main thread
        self.root.after(0, lambda: self.receive_progress_var.set(progress))
        
        if message:
            self.log_to_receive(message)
    
    def update_progress(self, current, total, message=None):
        """General progress update callback - routes to active tab"""
        if self.tab_control.index(self.tab_control.select()) == 0:
            self.update_send_progress(current, total, message)
        else:
            self.update_receive_progress(current, total, message)
    
    def update_transfer_status(self, transfer_id, status, message=None):
        """Update transfer status in UI based on network manager callbacks"""
        if message:
            if status == TransferStatus.WAITING or status == TransferStatus.CONNECTING:
                self.log_to_send(message)
            else:
                self.log_to_receive(message)
                
        # Update status bar
        self.root.after(0, lambda: self.status_var.set(message if message else status))
    
    def log_to_send(self, message):
        """Add a message to the send log"""
        self.root.after(0, lambda: self._append_to_log(self.send_log, message))
    
    def log_to_receive(self, message):
        """Add a message to the receive log"""
        self.root.after(0, lambda: self._append_to_log(self.receive_log, message))
    
    def _append_to_log(self, log_widget, message):
        """Append a message to a log widget with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        log_widget.config(state=tk.NORMAL)
        log_widget.insert(tk.END, f"[{timestamp}] {message}\n")
        log_widget.see(tk.END)
        log_widget.config(state=tk.DISABLED)
    
    def _add_to_history(self, transfer_id, transfer_type, filepath, status):
        """Add a transfer to the history"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        filename = os.path.basename(filepath) if filepath else "Unknown"
        
        try:
            size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            size_str = self._format_size(size)
        except:
            size_str = "Unknown"
            
        # Insert at the beginning of the treeview
        self.root.after(0, lambda: self.history_tree.insert("", 0, values=(
            timestamp, transfer_type, filename, size_str, status
        )))
        
        # TODO: Save transfer history to a database or file
    
    def load_transfer_history(self):
        """Load transfer history from storage"""
        # TODO: Implement loading from a database or file
        # For now, we'll just add a sample entry
        self.history_tree.insert("", 0, values=(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "sample",
            "example.txt",
            "1 KB",
            "Complete"        ))
    
    def _format_size(self, size_bytes):
        """Format a file size in bytes to a human-readable string"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Copied to clipboard")
        
    def paste_from_clipboard(self):
        """Paste RSA public key from clipboard for decryption"""
        try:
            text = self.root.clipboard_get()
            # Try to validate that it's a valid RSA key
            if "-----BEGIN PUBLIC KEY-----" in text and "-----END PUBLIC KEY-----" in text:
                # Try to parse the key
                key_type = "unknown"
                try:
                    key, key_type = self.encryption_manager.parse_pem_key(text)
                    if key and key_type == "rsa":
                        # Insert the RSA key
                        self.sender_key_text.delete("1.0", tk.END)
                        self.sender_key_text.insert("1.0", text)
                        self.log_to_receive("✓ Valid RSA public key pasted - ready for decryption")
                        self.log_to_receive("Signatures will be verified automatically when receiving files")
                        self.status_var.set("RSA public key pasted successfully")
                        return text
                    elif key and key_type == "ec":
                        self.log_to_receive("⚠️ Warning: EC keys cannot be used for decryption")
                        self.log_to_receive("Please paste an RSA public key instead")
                        self.status_var.set("EC key detected - RSA key required")
                        return None
                    else:
                        self.log_to_receive("Warning: Could not determine key type - please paste an RSA public key")
                        return None
                except Exception as e:
                    self.log_to_receive(f"Key parsing error: {e}")
                    return None
            else:
                # Insert the text but warn
                self.sender_key_text.delete("1.0", tk.END)
                self.sender_key_text.insert("1.0", text)
                self.log_to_receive("⚠️ Warning: The pasted text doesn't appear to be a valid RSA public key")
                self.log_to_receive("Make sure you're pasting an RSA public key for decryption")
                self.status_var.set("Invalid key format")
        except Exception as e:
            self.status_var.set(f"Clipboard error: {e}")
            self.log_to_receive("Could not access clipboard")
    
    def open_settings(self):
        """Open the settings window"""
        settings_dialog = SettingsDialog(self.root)
    
    def show_user_guide(self):
        """Show the user guide"""
        user_guide = UserGuideDialog(self.root)
    
    def show_about(self):
        """Show about dialog"""
        about_dialog = AboutDialog(self.root)
    
    def on_settings_changed(self, new_settings):
        """
        Handle changes to application settings
        This is called when settings are updated via the Settings dialog
        """
        # Update the file processor chunk size if it changed
        if hasattr(self, 'file_processor') and new_settings.get('chunk_size'):
            print(f"Updating chunk size to {new_settings.get('chunk_size')} bytes")
            self.file_processor.chunk_size = new_settings.get('chunk_size')
            self.add_log_message(f"Updated chunk size to {new_settings.get('chunk_size')/1024/1024:.1f} MB")
        
        # Update digital signature algorithm if changed
        if hasattr(self, 'digital_signature') and new_settings.get('signature_algorithm'):
            if new_settings.get('signature_algorithm') == "SHA256":
                self.digital_signature.algorithm = SignatureAlgorithm.SHA256
                self.add_log_message("Signature algorithm set to SHA-256")
            elif new_settings.get('signature_algorithm') == "SHA512":
                self.digital_signature.algorithm = SignatureAlgorithm.SHA512
                self.add_log_message("Signature algorithm set to SHA-512")
        
        # Update encryption strength if changed
        if new_settings.get('encryption_strength'):
            # Note: This won't affect existing keys, but will be used for any new keys
            self.add_log_message(f"Encryption strength set to {new_settings.get('encryption_strength')}")
            print(f"Encryption strength set to {new_settings.get('encryption_strength')}")
        
        # Update network manager default port
        if hasattr(self, 'network_manager') and new_settings.get('default_port'):
            self.network_manager.default_port = new_settings.get('default_port')
        
        # Update UI port field
        if hasattr(self, 'port_var') and new_settings.get('default_port'):
            self.port_var.set(str(new_settings.get('default_port')))
        
        # Update UI connection type
        if hasattr(self, 'connection_type_var') and new_settings.get('default_connection_type'):
            conn_type = new_settings.get('default_connection_type')
            if conn_type == "local":
                self.connection_type_var.set(ConnectionType.LOCAL)
            elif conn_type == "direct":
                self.connection_type_var.set(ConnectionType.DIRECT)
            elif conn_type == "ngrok":
                self.connection_type_var.set(ConnectionType.NGROK)
        
        # Load the updated settings
        self.settings = self.db_manager.get_settings()
        
        # Log the changes
        self.add_log_message("Settings updated successfully")
    
    def add_log_message(self, message):
        """Add a message to the appropriate log based on the active tab"""
        current_tab = self.tab_control.index(self.tab_control.select())
        if current_tab == 0:
            self.log_to_send(message)
        elif current_tab == 1:
            self.log_to_receive(message)
        else:
            # If in history tab or otherwise, update status bar only
            self.status_var.set(message)
    
    def schedule_periodic_cleanup(self):
        """Schedule periodic cleanup every 6 hours"""
        def periodic_cleanup():
            try:
                self.db_manager.cleanup_old_transfers(days_old=1)
                print("Periodic cleanup completed")
            except Exception as e:
                print(f"Error during periodic cleanup: {e}")
            
            # Schedule next cleanup in 6 hours (21600000 ms)
            self.root.after(21600000, periodic_cleanup)
        
        # Start the first cleanup after 6 hours
        self.root.after(21600000, periodic_cleanup)
    
    def on_closing(self):
        """Handle application closing with cleanup"""
        try:
            self.db_manager.shutdown_cleanup()
        except Exception as e:
            print(f"Error during shutdown cleanup: {e}")
        self.root.destroy()

    def run(self):
        """Start the main application loop"""
        # Set up cleanup on window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
