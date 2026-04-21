import socket
import threading
import os
import sys
import hashlib
import smtplib
import requests
import random
import string
import time
import subprocess
import re
import zipfile
import json
import tempfile
import webbrowser
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, send_from_directory, Response

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════
#  SHARED CONFIGURATION
# ═══════════════════════════════════════════════════════════════
PORT     = 5001          # LAN socket port
WEB_PORT = 5050          # Flask UI port
BUFFER   = 4096
PASSWORD = b"StrongPassword123"

APP_PASSWORD = "acjk hxfz gbps hsqj"   # Gmail App Password
OTP_EXPIRY   = 300                      # 5 minutes

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB upload limit

@app.after_request
def add_headers(response):
    # Allow browser fetch() from the same origin; also fixes SSE in some browsers
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

# ── Server-side state (shared across requests) ────────────────
srv = {
    'otp':          None,
    'otp_sent_at':  None,
    'otp_attempts': 3,
    'lan_conn':     None,
    'lan_role':     None,
    'lan_logs':     [],
    'lan_server_sock': None,
}


# ═══════════════════════════════════════════════════════════════
#  CRYPTO HELPERS
# ═══════════════════════════════════════════════════════════════
def generate_key(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=100000, backend=default_backend()
    )
    return kdf.derive(PASSWORD)

def encrypt_data(data, key):
    iv = os.urandom(16)
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()

def decrypt_data(data, key):
    iv, encrypted = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(encrypted) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def recv_exact(conn, size):
    data = b""
    try:
        while len(data) < size:
            packet = conn.recv(size - len(data))
            if not packet:
                return None
            data += packet
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        return None
    return data


# ═══════════════════════════════════════════════════════════════
#  OTP
# ═══════════════════════════════════════════════════════════════
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(sender_email):
    otp = generate_otp()
    body = (
        f"Hello,\n\nYour OTP to verify and send files is:\n\n"
        f"    🔐  {otp}\n\nValid for {OTP_EXPIRY // 60} minutes.\n"
        f"Do not share this with anyone."
    )
    msg = MIMEMultipart()
    msg["From"]    = sender_email
    msg["To"]      = sender_email
    msg["Subject"] = "Your Sender Verification OTP"
    msg.attach(MIMEText(body, "plain"))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, APP_PASSWORD)
            server.sendmail(sender_email, sender_email, msg.as_string())
        return otp, time.time()
    except Exception as e:
        print(f"   OTP send error: {e}")
        return None, None


# ═══════════════════════════════════════════════════════════════
#  YARA / BINWALK SCAN
# ═══════════════════════════════════════════════════════════════
def load_yara_rules(rules_dir="yara_rules"):
    if not YARA_AVAILABLE or not os.path.isdir(rules_dir):
        return None
    rule_files = [
        os.path.join(rules_dir, f)
        for f in os.listdir(rules_dir)
        if f.lower().endswith(('.yar', '.yara'))
    ]
    if not rule_files:
        return None
    try:
        return yara.compile(filepath=rule_files)
    except Exception as e:
        print(f"YARA compile error: {e}")
        return None

YARA_RULES = load_yara_rules()

def _describe_zip(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            infos = z.infolist()
            return {
                'total_files':  len(infos),
                'uncompressed': sum(i.file_size for i in infos),
                'compressed':   sum(i.compress_size for i in infos),
                'entries': [
                    {'name': i.filename, 'size': i.file_size, 'comp': i.compress_size}
                    for i in infos[:5]
                ]
            }
    except Exception as exc:
        return {'error': str(exc)}

def run_binwalk_scan(file_path):
    findings = []
    try:
        import binwalk
        for module in binwalk.scan(file_path, signature=True, quiet=True):
            for result in module.results:
                findings.append({"offset": hex(result.offset), "desc": result.description})
    except ImportError:
        try:
            result = subprocess.run(
                ["binwalk", file_path], capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        findings.append({"offset": parts[1], "desc": parts[2]})
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass

    yara_matches = []
    if YARA_RULES:
        try:
            for m in YARA_RULES.match(file_path):
                meta_threat = m.meta.get("threat") if isinstance(m.meta, dict) else None
                desc = f"YARA rule: {m.rule}"
                if meta_threat:
                    desc += f"  (threat: {meta_threat})"
                yara_matches.append(desc)
        except Exception:
            pass

    result = {"binwalk": findings, "yara": yara_matches}
    if findings and any("ZIP archive" in f["desc"] for f in findings):
        if zipfile.is_zipfile(file_path):
            result["zip_info"] = _describe_zip(file_path)
    return result


# ═══════════════════════════════════════════════════════════════
#  GOFILE UPLOAD
# ═══════════════════════════════════════════════════════════════
def upload_to_gofile(file_path):
    file_name = os.path.basename(file_path)
    # Step 1: get best server
    try:
        res = requests.get("https://api.gofile.io/servers", timeout=10)
        data = res.json()
        # API v2: {"status":"ok","data":{"servers":[{"name":"store1",...}]}}
        servers = data.get("data", {}).get("servers", [])
        if servers:
            server = servers[0]["name"]
        else:
            server = "store1"  # fallback
        url = f"https://{server}.gofile.io/contents/uploadfile"
    except Exception as e:
        return None, f"GoFile server lookup failed: {e}"
    # Step 2: upload
    try:
        with open(file_path, "rb") as f:
            response = requests.post(url, files={"file": (file_name, f)}, timeout=120)
        result = response.json()
    except Exception as e:
        return None, f"Upload request failed: {e}"
    if result.get("status") == "ok":
        link = result.get("data", {}).get("downloadPage") or result.get("data", {}).get("link")
        if link:
            return link, None
        return None, "Upload succeeded but no download link in response"
    return None, str(result)


# ═══════════════════════════════════════════════════════════════
#  EMAIL SENDER
# ═══════════════════════════════════════════════════════════════
def send_final_email(sender_email, receiver_emails, file_links, message=None):
    file_section = ""
    for i, (fname, link) in enumerate(file_links, 1):
        file_section += f"  {i}. {fname}\n     🔗 {link}\n\n"
    msg_section = ""
    if message:
        msg_section = (
            f"\n─────────────────────────────────────────\n"
            f"📝 MESSAGE FROM {sender_email}:\n"
            f"─────────────────────────────────────────\n"
            f"{message}\n"
            f"─────────────────────────────────────────\n"
        )
    subject = f"{len(file_links)} File(s) Shared With You"
    body = (
        f"Hello,\n\n{len(file_links)} file(s) have been shared with you via GoFile.\n"
        f"{msg_section}\n📁 YOUR DOWNLOAD LINK(S):\n{file_section}"
        f"Click each link to view and download.\n"
        f"No GoFile account needed — links are publicly accessible.\n\n"
        f"Sent by: {sender_email}\n"
    )
    errors = []
    for receiver in receiver_emails:
        msg = MIMEMultipart()
        msg["From"]    = sender_email
        msg["To"]      = receiver
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, APP_PASSWORD)
                server.sendmail(sender_email, receiver, msg.as_string())
        except Exception as e:
            errors.append(f"{receiver}: {e}")
    return errors


# ═══════════════════════════════════════════════════════════════
#  LAN HELPERS
# ═══════════════════════════════════════════════════════════════
def lan_log(type_, msg):
    srv['lan_logs'].append({'type': type_, 'msg': msg, 'time': time.strftime('%H:%M:%S')})
    print(f"[LAN/{type_}] {msg}")

def lan_receive_loop(conn):
    """Receive files from peer and save them; logs go to srv['lan_logs']."""
    while True:
        try:
            salt = recv_exact(conn, 16)
            if not salt:
                lan_log('error', 'Remote disconnected.')
                srv['lan_conn'] = None
                break
            key         = generate_key(salt)
            raw_size    = recv_exact(conn, 4)
            if not raw_size:
                break
            header_size = int.from_bytes(raw_size, 'big')
            raw_header  = recv_exact(conn, header_size)
            if not raw_header:
                break
            header = decrypt_data(raw_header, key).decode()
            if header == "stop":
                lan_log('info', 'Connection closed by remote.')
                srv['lan_conn'] = None
                break
            file_name, enc_size = header.split("|")
            enc_size = int(enc_size)
            encrypted_data = b""
            received = 0
            while received < enc_size:
                try:
                    chunk = conn.recv(min(BUFFER, enc_size - received))
                except Exception:
                    break
                if not chunk:
                    break
                encrypted_data += chunk
                received += len(chunk)
            decrypted   = decrypt_data(encrypted_data, key)
            raw_hash    = recv_exact(conn, 64)
            if not raw_hash:
                break
            if raw_hash.decode() == hashlib.sha256(decrypted).hexdigest():
                save_path = os.path.join(os.getcwd(), file_name)
                with open(save_path, "wb") as f:
                    f.write(decrypted)
                lan_log('success', f"'{file_name}' received and saved — integrity verified")
            else:
                lan_log('error', f"'{file_name}' integrity check FAILED — discarded")
        except Exception as e:
            lan_log('error', f'Receive error: {e}')
            break


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — UI
# ═══════════════════════════════════════════════════════════════
@app.route('/')
def index():
    # Serve 2u.html from same directory as this script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(base_dir, '2u.html')


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — OTP
# ═══════════════════════════════════════════════════════════════
@app.route('/api/otp/send', methods=['POST'])
def api_otp_send():
    data  = request.get_json()
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'error': 'Email required'}), 400
    otp, sent_at = send_otp_email(email)
    if otp:
        srv['otp']          = otp
        srv['otp_sent_at']  = sent_at
        srv['otp_attempts'] = 3
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to send OTP — check APP_PASSWORD'}), 500

@app.route('/api/otp/verify', methods=['POST'])
def api_otp_verify():
    data    = request.get_json()
    entered = data.get('otp', '').strip()
    if not srv['otp']:
        return jsonify({'success': False, 'error': 'No OTP sent yet'})
    if time.time() - srv['otp_sent_at'] > OTP_EXPIRY:
        return jsonify({'success': False, 'error': 'OTP expired — resend'})
    if entered == srv['otp']:
        srv['otp'] = None   # invalidate after use
        return jsonify({'success': True})
    srv['otp_attempts'] -= 1
    remaining = srv['otp_attempts']
    if remaining <= 0:
        return jsonify({'success': False, 'error': 'Too many attempts', 'remaining': 0})
    return jsonify({'success': False, 'error': 'Wrong OTP', 'remaining': remaining})


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — SCAN
# ═══════════════════════════════════════════════════════════════
@app.route('/api/scan', methods=['POST'])
def api_scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f   = request.files['file']
    ext = os.path.splitext(f.filename)[1] or '.tmp'
    # Use a named temp file; on Windows delete=False is needed to read it after save
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    try:
        f.save(tmp.name)
        tmp.close()
        results = run_binwalk_scan(tmp.name)
    except Exception as e:
        results = {'binwalk': [], 'yara': [], 'error': str(e)}
    finally:
        try: os.unlink(tmp.name)
        except Exception: pass
    return jsonify(results)


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — UPLOAD TO GOFILE
# ═══════════════════════════════════════════════════════════════
@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    f     = request.files['file']
    fname = f.filename or 'upload.bin'
    ext   = os.path.splitext(fname)[1] or '.bin'
    tmp   = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    try:
        f.save(tmp.name)
        tmp.close()
        link, err = upload_to_gofile(tmp.name)
    except Exception as e:
        link, err = None, str(e)
    finally:
        try: os.unlink(tmp.name)
        except Exception: pass
    if link:
        return jsonify({'success': True, 'link': link, 'filename': fname})
    return jsonify({'success': False, 'error': err or 'Upload failed'}), 500


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — SEND EMAIL
# ═══════════════════════════════════════════════════════════════
@app.route('/api/email/send', methods=['POST'])
def api_email_send():
    data       = request.get_json()
    sender     = data.get('sender', '')
    receivers  = data.get('receivers', [])
    file_links = [(item['name'], item['link']) for item in data.get('file_links', [])]
    message    = data.get('message') or None
    errors     = send_final_email(sender, receivers, file_links, message)
    if not errors:
        return jsonify({'success': True})
    return jsonify({'success': False, 'errors': errors}), 500


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES — LAN
# ═══════════════════════════════════════════════════════════════
@app.route('/api/lan/server/start', methods=['POST'])
def api_lan_server_start():
    if srv.get('lan_conn'):
        return jsonify({'success': False, 'error': 'Already connected'})

    hostname = socket.gethostname()
    try:
        lan_ip = socket.gethostbyname(hostname)
    except Exception:
        lan_ip = '127.0.0.1'

    def run_server():
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("", PORT))
            server_sock.listen(1)
            srv['lan_server_sock'] = server_sock
            lan_log('info', f'Listening on port {PORT}…')
            conn, addr = server_sock.accept()
            srv['lan_conn'] = conn
            srv['lan_role'] = 'server'
            lan_log('success', f'Client connected from {addr[0]}')
            threading.Thread(target=lan_receive_loop, args=(conn,), daemon=True).start()
        except OSError as e:
            lan_log('error', f'Server error: {e}')

    threading.Thread(target=run_server, daemon=True).start()
    return jsonify({'success': True, 'ip': lan_ip, 'port': PORT})

@app.route('/api/lan/client/connect', methods=['POST'])
def api_lan_client_connect():
    data = request.get_json()
    ip   = data.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((ip, PORT))
        srv['lan_conn'] = conn
        srv['lan_role'] = 'client'
        lan_log('success', f'Connected to server at {ip}')
        threading.Thread(target=lan_receive_loop, args=(conn,), daemon=True).start()
        return jsonify({'success': True})
    except ConnectionRefusedError:
        return jsonify({'success': False, 'error': f'Connection refused at {ip}:{PORT}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/lan/send', methods=['POST'])
def api_lan_send():
    conn = srv.get('lan_conn')
    if not conn:
        return jsonify({'success': False, 'error': 'Not connected'}), 400
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    f         = request.files['file']
    data      = f.read()
    file_name = f.filename
    salt            = os.urandom(16)
    key             = generate_key(salt)
    encrypted_data  = encrypt_data(data, key)
    header          = f"{file_name}|{len(encrypted_data)}".encode()
    encrypted_header = encrypt_data(header, key)
    try:
        conn.send(salt)
        conn.send(len(encrypted_header).to_bytes(4, 'big'))
        conn.send(encrypted_header)
        sent = 0
        while sent < len(encrypted_data):
            chunk = encrypted_data[sent:sent + BUFFER]
            conn.sendall(chunk)
            sent += len(chunk)
        conn.send(hashlib.sha256(data).hexdigest().encode())
        lan_log('success', f"'{file_name}' sent — SHA-256 integrity verified")
        return jsonify({'success': True})
    except Exception as e:
        lan_log('error', f'Send error: {e}')
        srv['lan_conn'] = None
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/lan/disconnect', methods=['POST'])
def api_lan_disconnect():
    conn = srv.get('lan_conn')
    if conn:
        try:
            salt = os.urandom(16)
            key  = generate_key(salt)
            enc  = encrypt_data(b"stop", key)
            conn.send(salt)
            conn.send(len(enc).to_bytes(4, 'big'))
            conn.send(enc)
            conn.close()
        except Exception:
            pass
    srv['lan_conn'] = None
    srv['lan_role'] = None
    lan_log('info', 'Disconnected.')
    return jsonify({'success': True})

@app.route('/api/lan/status')
def api_lan_status():
    hostname = socket.gethostname()
    try:
        lan_ip = socket.gethostbyname(hostname)
    except Exception:
        lan_ip = '127.0.0.1'
    return jsonify({
        'connected': srv['lan_conn'] is not None,
        'role':      srv.get('lan_role'),
        'ip':        lan_ip
    })

@app.route('/api/lan/logs')
def api_lan_logs():
    """Server-Sent Events stream for LAN log messages."""
    def generate():
        last = 0
        while True:
            logs = srv['lan_logs']
            while last < len(logs):
                yield f"data: {json.dumps(logs[last])}\n\n"
                last += 1
            time.sleep(0.25)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    url = f'http://127.0.0.1:{WEB_PORT}'
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║          🔒 Secure File Transfer Suite               ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  UI  →  {url:<44}║")
    print("║  Keep this window open while using the UI           ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    print("  Opening browser automatically…")
    print("  Press Ctrl+C to stop the server.\n")
    # Open browser after 1 second (give Flask time to start)
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host='127.0.0.1', port=WEB_PORT, debug=False, threaded=True)
