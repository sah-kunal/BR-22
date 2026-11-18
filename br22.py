import socket
import os
import sys
import zipfile
import hashlib
import argparse
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DEFAULT_PORT = 4444
DEFAULT_BUFFER = 64

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

def get_cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def prepare_target(target_path, quiet):
    if os.path.isfile(target_path):
        return target_path, False
    
    if not quiet: print(f"[*] Compressing folder '{target_path}'...")
    zip_name = f"{os.path.basename(os.path.normpath(target_path))}.zip"
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, start=target_path))
    return zip_name, True

def send_data(args):
    buffer_size = args.buffer * 1024
    file_to_send, is_zipped = prepare_target(args.target, args.quiet)
    
    if not os.path.exists(file_to_send):
        print("[-] Target not found.")
        return

    filesize = os.path.getsize(file_to_send)
    file_md5 = calculate_md5(file_to_send)

    s = socket.socket()
    if not args.quiet: print(f"[*] Establishing connection to {args.ip}:{args.port}...")
    try:
        s.connect((args.ip, args.port))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    metadata = f"{os.path.basename(file_to_send)}|{filesize}|{file_md5}|{is_zipped}"
    padded_metadata = metadata.ljust(512, ' ').encode()

    # Agar password hai, toh Encrypted (1), warna Plaintext (0)
    if args.password:
        if not args.quiet: print("[*] Mode: ENCRYPTED (AES-256)")
        s.send(b'1')  # Flag indicating encryption is ON
        key = derive_key(args.password)
        iv = os.urandom(16)
        s.send(iv)
        encryptor = get_cipher(key, iv).encryptor()
        s.send(encryptor.update(padded_metadata))
    else:
        if not args.quiet: print("[*] Mode: PLAINTEXT (Fast Transfer)")
        s.send(b'0')  # Flag indicating encryption is OFF
        s.send(padded_metadata)

    progress = None
    if not args.quiet:
        progress = tqdm(range(filesize), f"Sending", unit="B", unit_scale=True, unit_divisor=1024)
    
    with open(file_to_send, "rb") as f:
        while True:
            bytes_read = f.read(buffer_size)
            if not bytes_read:
                break
            
            if args.password:
                s.sendall(encryptor.update(bytes_read))
            else:
                s.sendall(bytes_read)
                
            if progress: progress.update(len(bytes_read))
    
    s.close()
    if is_zipped: os.remove(file_to_send)
    if not args.quiet: print("\n[+] Transfer Complete!")

def receive_data(args):
    buffer_size = args.buffer * 1024
    s = socket.socket()
    s.bind(("0.0.0.0", args.port))
    s.listen(1)
    
    if not args.quiet: print(f"[*] Server listening on port {args.port}...")
    
    client_socket, address = s.accept()
    if not args.quiet: print(f"[+] Connection received from {address[0]}")

    # Check first byte to see if sender used encryption
    is_encrypted = client_socket.recv(1) == b'1'

    if is_encrypted:
        if not args.password:
            print("\n[-] ERROR: Sender used a password, but you didn't provide one to decrypt!")
            client_socket.close()
            s.close()
            return
            
        key = derive_key(args.password)
        iv = client_socket.recv(16)
        decryptor = get_cipher(key, iv).decryptor()
        enc_metadata = client_socket.recv(512)
        dec_metadata = decryptor.update(enc_metadata).decode('utf-8', errors='ignore').strip()
    else:
        if args.password:
            print("\n[-] WARNING: You provided a password, but the sender sent data in PLAINTEXT. Ignoring password.")
        dec_metadata = client_socket.recv(512).decode('utf-8', errors='ignore').strip()
    
    try:
        filename, filesize, original_md5, is_zipped = dec_metadata.split('|')
        filesize = int(filesize)
        is_zipped = is_zipped == "True"
    except:
        print("\n[-] FATAL ERROR: Corrupted Data or Incorrect Password.")
        client_socket.close()
        s.close()
        return

    progress = None
    if not args.quiet:
        progress = tqdm(range(filesize), f"Receiving", unit="B", unit_scale=True, unit_divisor=1024)
        
    with open(filename, "wb") as f:
        received_bytes = 0
        while received_bytes < filesize:
            chunk = client_socket.recv(buffer_size)
            if not chunk:
                break
                
            if is_encrypted:
                f.write(decryptor.update(chunk))
            else:
                f.write(chunk)
                
            received_bytes += len(chunk)
            if progress: progress.update(len(chunk))
            
    client_socket.close()
    s.close()
    
    if calculate_md5(filename) == original_md5:
        if not args.quiet: print("\n[+] Integrity Verified: File received successfully.")
    else:
        print("\n[-] WARNING: File Corrupted during transfer!")
        
    if is_zipped:
        extract_dir = filename.replace('.zip', '')
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        os.remove(filename)
        if not args.quiet: print(f"[+] Payload extracted to '{extract_dir}'")

def main():
    banner = """
  ____  ____       ___  ___  
 | __ )|  _ \     |__ \|__ \ 
 |  _ \| |_) |_____ / /  / / 
 | |_) |  _ <_____|/ /_ / /_ 
 |____/|_| \_\    /____/____|
                             
    BR-22: Advanced P2P File Transfer Tool
    """
    
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=banner)

    core = parser.add_argument_group('Core Options')
    core.add_argument("-m", "--mode", choices=["send", "receive"], required=True, help="Set operation mode (send / receive)")
    # PASSWORD AB OPTIONAL HAI (required=False)
    core.add_argument("--password", required=False, help="Optional: Authentication Key for AES-256 Encryption")
    
    target = parser.add_argument_group('Target Options')
    target.add_argument("-t", "--target", help="File or Folder path to send (Required if mode=send)")
    target.add_argument("-i", "--ip", help="Target IP Address (Required if mode=send)")
    target.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"Target/Bind Port (Default: {DEFAULT_PORT})")
    
    adv = parser.add_argument_group('Advanced Tuning')
    adv.add_argument("-b", "--buffer", type=int, default=DEFAULT_BUFFER, help=f"Buffer size in KB (Default: {DEFAULT_BUFFER})")
    adv.add_argument("-q", "--quiet", action="store_true", help="Stealth Mode: Hide progress bar and standard output")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.mode == "send":
        if not args.target or not args.ip:
            parser.error("Sender mode requires --target (-t) and --ip (-i)")
        send_data(args)
    elif args.mode == "receive":
        receive_data(args)

if __name__ == "__main__":
    main()
