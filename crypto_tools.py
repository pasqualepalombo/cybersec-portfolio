#!/usr/bin/env python3
"""
Crypto Tools Suite
1. Password Hash Cracker (Dictonary Attack)
2. Dile Encryptor/Decryptor
"""

import hashlib
import sys
from cryptography.fernet import Fernet
from colorama import Fore, Style, init

init(autoreset=True)


# ==== TOOL 1: Password Hash Cracker ===== #
"""
Hashes password with different algorithms
"""
def hash_password(password, algorithm='sha256'):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        print(f"{Fore.RED}[!] Unsupported algorithm")
        return None

def crack_hash(target_hash, wordlist_file, algorithm='sha256'):
    print(f"{Fore.CYAN}[*] Starting hash crack...")
    print(f"{Fore.CYAN}[*] Target hash: {target_hash}")
    print(f"{Fore.CYAN}[*] Algorithm: {algorithm}")
    print(f"{Fore.CYAN}[*] Wordlist {wordlist_file}")

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            attempts = 0
            for line in f:
                password = line.strip()
                attempts += 1

                if attempts % 1000 == 0:
                    print(f"{Fore.YELLOW}[*] Tried {attempts} passwords...", end='\r')
                
                # hashing e confronto
                password_hash = hash_password(password, algorithm)
                if password_hash == target_hash:
                    print(f"{Fore.GREEN}[✓] PASSWORD FOUND!")
                    print(f"{Fore.GREEN}[✓] Password: {password}")
                    print(f"{Fore.GREEN}[✓] Attempts: {attempts}")
                    return password
            
            print(f"\n{Fore.RED}[!] Password not found in wordlist!")
            print(f"{Fore.RED}[!] Total attempts: {attempts}")
            return None
        
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Wordlist not found: {wordlist_file}")
        return None

# ====== TOOL 2: File Encryptor ======= #
"""
Generate encryption key and save to file
"""
def generate_key():
    key = Fernet.generate_key()
    with open('encryption.key', 'wb') as key_file:
        key_file.write(key)
    print(f"{Fore.GREEN}[✓] Key generated and saved")
    return key

def load_key():
    try:
        return open('encryption.key', 'rb').read()
    except:
        print(f"{Fore.RED}[!] key file not found. Generate one first.")
        return None

"""
Encrypt a single file
"""
def encrypt_file(filename, key):
    try:
        fernet = Fernet(key)
        
        # Leggi file
        with open(filename, 'rb') as file:
            original = file.read()
        
        # Cifra
        encrypted = fernet.encrypt(original)
        
        # Salva file cifrato
        encrypted_filename = filename + '.encrypted'
        with open(encrypted_filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        
        print(f"{Fore.GREEN}[✓] File encrypted: {encrypted_filename}")
        return encrypted_filename
        
    except Exception as e:
        print(f"{Fore.RED}[!] Encryption error: {e}")
        return None

def decrypt_file(filename, key):
    try:
        fernet = Fernet(key)

        with open(filename, 'rb') as encrypted_file:
            encrypted = encrypted_file.read()
        
        decrypted = fernet.decrypt(encrypted)

        if filename.endswith('.encrypted'):
            decrypted_filename = filename[:-10]
        else:
            decrypted_filename = filename + '_decrypted'
        
        with open(decrypted_filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        
        print(f"{Fore.GREEN}[✓] File decrypted: {decrypted_filename}")
    except Exception as e:
        print(f"{Fore.RED}[!] Decryption error: {e}")
        return None

def menu():
    """
    Main menu
    """
    print(f"{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}           CRYPTO TOOLS SUITE")
    print(f"{Fore.CYAN}{'=' * 60}\n")
    
    print(f"{Fore.YELLOW}Select tool:")
    print("  1. Hash Password")
    print("  2. Crack Password Hash")
    print("  3. Generate Encryption Key")
    print("  4. Encrypt File")
    print("  5. Decrypt File")
    print("  0. Exit")
    
    choice = input(f"\n{Fore.CYAN}Choice: ").strip()
    
    if choice == '1':
        # Hash password
        password = input("Enter password to hash: ")
        print("\nAlgorithms: md5, sha1, sha256, sha512")
        algo = input("Algorithm (default sha256): ").strip() or 'sha256'
        
        hash_result = hash_password(password, algo)
        if hash_result:
            print(f"\n{Fore.GREEN}Hash ({algo}): {hash_result}")
    
    elif choice == '2':
        # Crack hash
        target = input("Enter hash to crack: ").strip()
        wordlist = input("Wordlist file (default: rockyou.txt): ").strip() or 'rockyou.txt'
        print("\nAlgorithms: md5, sha1, sha256, sha512")
        algo = input("Algorithm (default sha256): ").strip() or 'sha256'
        
        crack_hash(target, wordlist, algo)
    
    elif choice == '3':
        # Generate key
        generate_key()
    
    elif choice == '4':
        # Encrypt file
        filename = input("File to encrypt: ").strip()
        key = load_key()
        if key:
            encrypt_file(filename, key)
    
    elif choice == '5':
        # Decrypt file
        filename = input("File to decrypt: ").strip()
        key = load_key()
        if key:
            decrypt_file(filename, key)
    
    elif choice == '0':
        print(f"{Fore.CYAN}Goodbye!")
        sys.exit(0)
    
    else:
        print(f"{Fore.RED}[!] Invalid choice")
    
    input(f"\n{Fore.YELLOW}Press Enter to continue...")
    menu()  # Torna al menu

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user")
        sys.exit(0)