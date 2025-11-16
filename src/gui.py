"""
gui.py
Main GUI application for Digital Signature System.
Provides user-friendly interface for signing and verifying documents.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from signer import DocumentSigner
from verifier import SignatureVerifier
from metadata import MetadataManager
from utils import FileUtils


class DigitalSignatureGUI:
    """Main GUI application for digital signature system."""
    
    def __init__(self, root):
        """
        Initialize the GUI.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("Digital Signature System")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Initialize components
        self.signer = DocumentSigner()
        self.verifier = SignatureVerifier()
        
        # Create UI
        self.create_menu()
        self.create_main_interface()
        
        # Initialize with sign mode
        self.show_sign_mode()
    
    def create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Generate New Keys", command=self.generate_new_keys)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_main_interface(self):
        """Create main interface layout."""
        # Top frame for mode selection
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Select Operation Mode:", 
                 font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=10)
        
        self.mode_var = tk.StringVar(value="sign")
        
        ttk.Radiobutton(top_frame, text="Sign Document", 
                       variable=self.mode_var, value="sign",
                       command=self.show_sign_mode).pack(side=tk.LEFT, padx=10)
        
        ttk.Radiobutton(top_frame, text="Verify Signature", 
                       variable=self.mode_var, value="verify",
                       command=self.show_verify_mode).pack(side=tk.LEFT, padx=10)
        
        # Separator
        ttk.Separator(self.root, orient='horizontal').pack(fill=tk.X, pady=5)
        
        # Content frame (will be dynamically populated)
        self.content_frame = ttk.Frame(self.root, padding="10")
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output frame at bottom
        output_label = ttk.Label(self.root, text="Output:", font=('Arial', 10, 'bold'))
        output_label.pack(anchor=tk.W, padx=10)
        
        self.output_text = scrolledtext.ScrolledText(
            self.root, height=10, wrap=tk.WORD, 
            font=('Courier', 9), state='disabled'
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def clear_content_frame(self):
        """Clear all widgets from content frame."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_sign_mode(self):
        """Display signing interface."""
        self.clear_content_frame()
        self.clear_output()
        
        # Title
        ttk.Label(self.content_frame, text="Sign a Document", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Document selection
        doc_frame = ttk.LabelFrame(self.content_frame, text="Document Selection", padding="10")
        doc_frame.pack(fill=tk.X, pady=10)
        
        self.sign_doc_path = tk.StringVar()
        ttk.Entry(doc_frame, textvariable=self.sign_doc_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(doc_frame, text="Browse...", command=self.browse_document_to_sign).pack(side=tk.LEFT)
        
        # Options
        options_frame = ttk.LabelFrame(self.content_frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=10)
        
        self.generate_qr_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Generate QR Codes for Public Key", 
                       variable=self.generate_qr_var).pack(anchor=tk.W)
        
        # Key information
        key_frame = ttk.LabelFrame(self.content_frame, text="Key Information", padding="10")
        key_frame.pack(fill=tk.X, pady=10)
        
        info = self.signer.get_signing_info()
        
        if info['keys_exist']:
            ttk.Label(key_frame, text=f"✓ Keys found", 
                     foreground='green').pack(anchor=tk.W)
            ttk.Label(key_frame, text=f"Public Key: {info['public_key_path']}", 
                     font=('Courier', 8)).pack(anchor=tk.W)
            if 'public_key_fingerprint' in info:
                ttk.Label(key_frame, 
                         text=f"Fingerprint: {info['public_key_fingerprint'][:32]}...", 
                         font=('Courier', 8)).pack(anchor=tk.W)
        else:
            ttk.Label(key_frame, text="⚠ No keys found. Keys will be generated automatically.", 
                     foreground='orange').pack(anchor=tk.W)
        
        # Sign button
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Sign Document", 
                  command=self.perform_signing, 
                  style='Accent.TButton').pack()
    
    def show_verify_mode(self):
        """Display verification interface."""
        self.clear_content_frame()
        self.clear_output()
        
        # Title
        ttk.Label(self.content_frame, text="Verify Digital Signature", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Document selection
        doc_frame = ttk.LabelFrame(self.content_frame, text="Document", padding="10")
        doc_frame.pack(fill=tk.X, pady=5)
        
        self.verify_doc_path = tk.StringVar()
        ttk.Entry(doc_frame, textvariable=self.verify_doc_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(doc_frame, text="Browse...", 
                  command=self.browse_document_to_verify).pack(side=tk.LEFT)
        
        # Signature selection
        sig_frame = ttk.LabelFrame(self.content_frame, text="Signature File (.sig)", padding="10")
        sig_frame.pack(fill=tk.X, pady=5)
        
        self.verify_sig_path = tk.StringVar()
        ttk.Entry(sig_frame, textvariable=self.verify_sig_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_frame, text="Browse...", 
                  command=self.browse_signature).pack(side=tk.LEFT)
        
        # Public key selection
        key_frame = ttk.LabelFrame(self.content_frame, text="Public Key (.pem)", padding="10")
        key_frame.pack(fill=tk.X, pady=5)
        
        self.verify_key_path = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.verify_key_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Browse...", 
                  command=self.browse_public_key).pack(side=tk.LEFT)
        
        # Metadata selection (optional)
        meta_frame = ttk.LabelFrame(self.content_frame, text="Metadata (Optional)", padding="10")
        meta_frame.pack(fill=tk.X, pady=5)
        
        self.verify_meta_path = tk.StringVar()
        ttk.Entry(meta_frame, textvariable=self.verify_meta_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(meta_frame, text="Browse...", 
                  command=self.browse_metadata).pack(side=tk.LEFT)
        
        # Auto-detect button
        ttk.Button(self.content_frame, text="Auto-Detect Files", 
                  command=self.auto_detect_verification_files).pack(pady=10)
        
        # Verify button
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Verify Signature", 
                  command=self.perform_verification, 
                  style='Accent.TButton').pack()
    
    # File browsing methods
    def browse_document_to_sign(self):
        """Browse for document to sign."""
        filename = filedialog.askopenfilename(
            title="Select Document to Sign",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.sign_doc_path.set(filename)
    
    def browse_document_to_verify(self):
        """Browse for document to verify."""
        filename = filedialog.askopenfilename(
            title="Select Document to Verify",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.verify_doc_path.set(filename)
    
    def browse_signature(self):
        """Browse for signature file."""
        filename = filedialog.askopenfilename(
            title="Select Signature File",
            filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")]
        )
        if filename:
            self.verify_sig_path.set(filename)
    
    def browse_public_key(self):
        """Browse for public key."""
        filename = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if filename:
            self.verify_key_path.set(filename)
    
    def browse_metadata(self):
        """Browse for metadata file."""
        filename = filedialog.askopenfilename(
            title="Select Metadata File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.verify_meta_path.set(filename)
    
    def auto_detect_verification_files(self):
        """Auto-detect signature and metadata files based on document."""
        doc_path = self.verify_doc_path.get()
        
        if not doc_path:
            messagebox.showwarning("Warning", "Please select a document first.")
            return
        
        # Generate expected filenames
        doc_dir = os.path.dirname(doc_path)
        doc_basename = os.path.splitext(os.path.basename(doc_path))[0]
        
        # Look in signatures directory
        sig_dir = os.path.join(os.getcwd(), 'signatures')
        
        # Try to find signature file
        sig_candidates = [
            os.path.join(sig_dir, f"{doc_basename}.sig"),
            os.path.join(doc_dir, f"{doc_basename}.sig")
        ]
        
        for sig_path in sig_candidates:
            if FileUtils.file_exists(sig_path):
                self.verify_sig_path.set(sig_path)
                break
        
        # Try to find metadata file
        meta_candidates = [
            os.path.join(sig_dir, f"{doc_basename}_metadata.json"),
            os.path.join(doc_dir, f"{doc_basename}_metadata.json")
        ]
        
        for meta_path in meta_candidates:
            if FileUtils.file_exists(meta_path):
                self.verify_meta_path.set(meta_path)
                break
        
        # Try to find public key
        key_path = os.path.join(os.getcwd(), 'keys', 'public_key.pem')
        if FileUtils.file_exists(key_path):
            self.verify_key_path.set(key_path)
        
        self.log_output("Auto-detection complete. Please verify the file paths.")
    
    # Action methods
    def perform_signing(self):
        """Perform document signing."""
        doc_path = self.sign_doc_path.get()
        
        if not doc_path:
            messagebox.showerror("Error", "Please select a document to sign.")
            return
        
        self.clear_output()
        self.log_output("Starting signing process...\n")
        
        try:
            # Sign the document
            result = self.signer.sign_document(
                doc_path,
                generate_qr=self.generate_qr_var.get()
            )
            
            # Display results
            self.log_output("✓ Document signed successfully!\n")
            self.log_output(f"Document: {result['document']}")
            self.log_output(f"Signature: {result['signature']}")
            self.log_output(f"Metadata: {result['metadata']}")
            self.log_output(f"Public Key: {result['public_key']}")
            self.log_output(f"Fingerprint: {result['fingerprint']}\n")
            
            if 'qr_codes' in result:
                self.log_output("QR Codes generated:")
                for qr_type, qr_path in result['qr_codes'].items():
                    self.log_output(f"  {qr_type}: {qr_path}")
            
            messagebox.showinfo("Success", 
                              f"Document signed successfully!\n\n"
                              f"Signature saved to:\n{result['signature']}")
            
        except Exception as e:
            self.log_output(f"\n✗ Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to sign document:\n{str(e)}")
    
    def perform_verification(self):
        """Perform signature verification."""
        doc_path = self.verify_doc_path.get()
        sig_path = self.verify_sig_path.get()
        key_path = self.verify_key_path.get()
        meta_path = self.verify_meta_path.get()
        
        if not doc_path or not sig_path or not key_path:
            messagebox.showerror("Error", 
                               "Please select document, signature, and public key files.")
            return
        
        self.clear_output()
        self.log_output("Starting verification process...\n")
        
        try:
            # Verify the signature
            result = self.verifier.verify_document(
                doc_path,
                sig_path,
                key_path,
                meta_path if meta_path else None
            )
            
            # Display results
            self.log_output(str(result))
            
            if result.success:
                messagebox.showinfo("Verification Success", 
                                  "✓ Signature is VALID\n\n"
                                  "The document is authentic and has not been modified.")
            else:
                messagebox.showerror("Verification Failed", 
                                   "✗ Signature is INVALID\n\n"
                                   "The document may have been modified or "
                                   "the signature does not match.")
            
        except Exception as e:
            self.log_output(f"\n✗ Error: {str(e)}")
            messagebox.showerror("Error", f"Verification failed:\n{str(e)}")
    
    def generate_new_keys(self):
        """Generate new RSA key pair."""
        response = messagebox.askyesno(
            "Generate New Keys",
            "This will replace existing keys if any.\n\n"
            "Are you sure you want to continue?"
        )
        
        if response:
            try:
                private_key, public_key = self.signer.generate_keys(force=True)
                self.log_output(f"New keys generated:\n")
                self.log_output(f"  Private: {private_key}")
                self.log_output(f"  Public: {public_key}")
                
                messagebox.showinfo("Success", 
                                  f"New keys generated successfully!\n\n"
                                  f"Public Key: {public_key}")
                
                # Refresh the current view
                if self.mode_var.get() == "sign":
                    self.show_sign_mode()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate keys:\n{str(e)}")
    
    # Output methods
    def log_output(self, message):
        """
        Add message to output text area.
        
        Args:
            message (str): Message to display
        """
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
    
    def clear_output(self):
        """Clear output text area."""
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state='disabled')
    
    def show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About",
            "Digital Signature System v1.0\n\n"
            "A secure document signing and verification tool\n"
            "using RSA-2048 and SHA-256.\n\n"
            "Features:\n"
            "• RSA digital signatures\n"
            "• SHA-256 hashing\n"
            "• Timestamp metadata\n"
            "• QR code generation\n\n"
            "© 2024 Information Security Project"
        )


def main():
    """Main entry point for the application."""
    root = tk.Tk()
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')
    
    # Create and run application
    app = DigitalSignatureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()