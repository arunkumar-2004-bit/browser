#!/usr/bin/env python3
"""
🔒 SECURE FILE TRANSFER SERVER WITH WEB UI
Upload to GitHub + Access from Phone/PC via IP
"""
import socket
import threading
import os
import hashlib
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import time

PORT = 5001
BUFFER = 4096
PASSWORD = b"StrongPassword123"

class SecureFileServer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 SECURE FILE SERVER")
        self.root.geometry("900x700")
        self.root.configure(bg="#1a1b26")
        self.conn = None
        self.server = None
        self.running = False
        self.setup_ui()
    
    def setup_ui(self):
        # Header
        title = tk.Label(self.root, text="🔒 SECURE FILE SERVER", font=("Consolas", 24, "bold"), 
                        fg="#00ff88", bg="#1a1b26")
        title.pack(pady=20)
        
        # Server Status
        self.status_frame = tk.Frame(self.root, bg="#1a1b26")
        self.status_frame.pack(pady=10)
        
        self.status_label = tk.Label(self.status_frame, text="🟡 Server Stopped", 
                                   font=("Arial", 14, "bold"), fg="#ff5555", bg="#1a1b26")
        self.status_label.pack()
        
        self.ip_label = tk.Label(self.status_frame, text="Finding IP...", 
                               font=("Arial", 12), fg="#bbbbbb", bg="#1a1b26")
        self.ip_label.pack()
        
        # Control Buttons
        btn_frame = tk.Frame(self.root, bg="#1a1b26")
        btn_frame.pack(pady=20)
        
        self.start_btn = tk.Button(btn_frame, text="🚀 START SERVER", command=self.start_server,
                                 bg="#00ff88", fg="black", font=("Arial", 16, "bold"),
                                 padx=40, pady=10, relief="flat")
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text="🛑 STOP SERVER", command=self.stop_server,
                                bg="#ff5555", fg="white", font=("Arial", 16, "bold"),
                                padx=40, pady=10, relief="flat", state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        # Received Files
        files_frame = tk.LabelFrame(self.root, text="📥 RECEIVED FILES", font=("Arial", 14, "bold"),
                                  fg="#00ff88", bg="#24283b", padx=10, pady=10)
        files_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Listbox with scrollbar
        list_frame = tk.Frame(files_frame, bg="#24283b")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.files_listbox = tk.Listbox(list_frame, bg="#1a1b26", fg="#ffffff",
                                      font=("Consolas", 11), selectbackground="#00ff88",
                                      height=15)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.files_listbox.yview)
        self.files_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Progress
        self.progress = ttk.Progressbar(self.root, mode='determinate', length=400)
        self.progress.pack(pady=10)
        
        self.get_local_ip()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.ip_label.config(text=f"🌐 Server IP: {ip}:{PORT}")
            self.server_ip = ip
        except:
            self.ip_label.config(text="❌ Could not detect IP")
    
    def start_server(self):
        if self.running:
            return
        threading.Thread(target=self.server_loop, daemon=True).start()
    
    def server_loop(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("", PORT))
            self.server.listen(5)
            
            self.running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.update_status("🟢 Server Started - Waiting for clients...", "#00ff88")
            
            while self.running:
                self.conn, addr = self.server.accept()
                self.update_status(f"✅ Client Connected: {addr[0]}", "#00ff88")
                threading.Thread(target=self.handle_client, args=(self.conn,), daemon=True).start()
                
        except Exception as e:
            self.update_status(f"❌ Server Error: {str(e)}", "#ff5555")
    
    def handle_client(self, conn):
        try:
            while self.running:
                salt = self.recv_exact(conn, 16)
                if not salt:
                    break
                
                key = self.generate_key(salt)
                header_size_bytes = self.recv_exact(conn, 4)
                header_size = int.from_bytes(header_size_bytes, 'big')
                encrypted_header = self.recv_exact(conn, header_size)
                header = self.decrypt_data(encrypted_header, key).decode()
                
                if header == "stop":
                    self.files_listbox.insert(0, "🔌 Client disconnected")
                    break
                
                file_name, enc_size = header.split("|")
                enc_size = int(enc_size)
                
                self.progress['maximum'] = enc_size
                self.progress['value'] = 0
                
                encrypted_data = b""
                received = 0
                
                while received < enc_size:
                    chunk = conn.recv(min(BUFFER, enc_size - received))
                    if not chunk:
                        break
                    encrypted_data += chunk
                    received += len(chunk)
                    self.progress['value'] = received
                    self.root.update_idletasks()
                
                decrypted = self.decrypt_data(encrypted_data, key)
                received_hash = self.recv_exact(conn, 64).decode()
                calculated_hash = hashlib.sha256(decrypted).hexdigest()
                
                if received_hash == calculated_hash:
                    save_path = os.path.join("received_files", file_name)
                    os.makedirs("received_files", exist_ok=True)
                    with open(save_path, "wb") as f:
                        f.write(decrypted)
                    self.files_listbox.insert(0, f"✅ {file_name} ({received/1024:.1f}KB)")
                    self.update_status("✔ File received & verified", "#00ff88")
                else:
                    self.files_listbox.insert(0, f"❌ {file_name} (Integrity Failed)")
                    self.update_status("❌ Integrity check failed", "#ff5555")
                    
        except Exception as e:
            self.files_listbox.insert(0, f"❌ Error: {str(e)}")
        finally:
            conn.close()
    
    # Crypto functions (unchanged from your original)
    def recv_exact(self, conn, size):
        data = b""
        while len(data) < size:
            packet = conn.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data
    
    def generate_key(self, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=100000, backend=default_backend())
        return kdf.derive(PASSWORD)
    
    def encrypt_data(self, data, key):
        iv = os.urandom(16)
        padder = sympadding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return iv + encrypted
    
    def decrypt_data(self, data, key):
        iv = data[:16]
        encrypted = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = sympadding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    
    def update_status(self, text, color):
        self.status_label.config(text=text, fg=color)
        self.root.update_idletasks()
    
    def stop_server(self):
        self.running = False
        if self.conn:
            self.conn.close()
        if self.server:
            self.server.close()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.update_status("🔴 Server Stopped", "#ff5555")
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.stop_server)
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureFileServer()
    app.run()
