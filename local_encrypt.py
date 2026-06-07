import os
import sys
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature
import base64

# Configuration
SALT_FILE = "salt.salt"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from the password using Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file(filename: str, password: str):
    """Encrypts a file in-place."""
    # 1. Generate or Load Salt
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        print(f"[+] New salt generated and saved to {SALT_FILE}")
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    
    # 2. Derive Key
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # 3. Encrypt Data
    try:
        with open(filename, "rb") as file:
            original_data = file.read()
        
        encrypted_data = fernet.encrypt(original_data)
        
        # Overwrite original file with encrypted data
        with open(filename, "wb") as file:
            file.write(encrypted_data)
            
        print(f"[SUCCESS] '{filename}' has been encrypted.")
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")

def decrypt_file(filename: str, password: str):
    """Decrypts a file in-place."""
    # 1. Load Salt
    if not os.path.exists(SALT_FILE):
        print("[ERROR] Salt file not found. Cannot decrypt.")
        return

    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    
    # 2. Derive Key
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # 3. Decrypt Data
    try:
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Overwrite with decrypted data
        with open(filename, "wb") as file:
            file.write(decrypted_data)
            
        print(f"[SUCCESS] '{filename}' has been decrypted.")
    except InvalidSignature:
        print("[ERROR] Decryption failed. Wrong password or corrupted file.")
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python3 {sys.argv[0]} <encrypt|decrypt> <filename>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    target_file = sys.argv[2]

    if not os.path.exists(target_file):
        print(f"[ERROR] File '{target_file}' not found.")
        sys.exit(1)

    # Securely get password
    password = getpass.getpass("Enter Password: ")

    if mode == "encrypt":
        encrypt_file(target_file, password)
    elif mode == "decrypt":
        decrypt_file(target_file, password)
    else:
        print("[ERROR] Invalid mode. Use 'encrypt' or 'decrypt'.")   
