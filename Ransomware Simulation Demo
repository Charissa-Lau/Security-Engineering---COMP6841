#!/usr/bin/env python3

"""
Safe NotPetya Demo Script
- Encrypts first 1MB of demo file with AES-128-CBC
- Simulates worm propagation via print statements
- Optional recovery mode (--demo-recover) for decryption
"""

import os
import argparse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import shutil
import secrets

# Timing constants for demo pacing
UPDATE_DELAY = 0.6
CHK_DELAY    = 0.8
REBOOT_DELAY = 1.0

def clear_screen():
    # Instead of clearing console, print blank lines to allow scrolling
    print('\n' * 5)

def print_centered(text, bold=False):
    width = shutil.get_terminal_size().columns
    line = text.center(width)
    if bold:
        print('\033[1m' + line + '\033[0m')
    else:
        print(line)

DEMO_FILE = 'demo.txt'
KEY_SIZE = 16  # 128 bits
CHUNK_SIZE = 1024 * 1024  # 1MB
IV_SIZE = 16
KEY_FILE = 'demo.key'


def generate_key_iv():
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(IV_SIZE)
    return key, iv


# Save key and IV to a file for later decryption
def save_key_iv(key, iv):
    # Persist key+iv for later decryption
    with open(KEY_FILE, 'wb') as f:
        f.write(key + iv)

# Load key and IV from a file
def load_key_iv():
    # Load persisted key+iv
    with open(KEY_FILE, 'rb') as f:
        data = f.read()
    return data[:KEY_SIZE], data[KEY_SIZE:]


def encrypt_file(key, iv):
    # create demo file if not exists
    if not os.path.exists(DEMO_FILE):
        with open(DEMO_FILE, 'wb') as f_out:
            f_out.write(b"This is a demo python file." * 1024)
    # read entire file
    with open(DEMO_FILE, 'rb') as f_in:
        full_data = f_in.read()
    data = full_data[:CHUNK_SIZE]
    rest = full_data[CHUNK_SIZE:]
    # pad and encrypt the first chunk
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    # write back ciphertext and remainder
    with open(DEMO_FILE, 'wb') as f_out:
        f_out.write(ct)
        f_out.write(rest)
    print("[What's aCtuAlly happening]")
    print(f"1. Encrypted first {len(data)} bytes of {DEMO_FILE}.")


def decrypt_file(key, iv):
    # read full encrypted content
    with open(DEMO_FILE, 'rb') as f_in:
        ct = f_in.read()
    # decrypt and unpad
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    # overwrite file with original data
    with open(DEMO_FILE, 'wb') as f_out:
        f_out.write(data)
    print(f"Decrypted and restored original content of {DEMO_FILE}.")


def simulate_propagation(hosts, creds):
    for host in hosts:
        print('\033[3m' + f"Attempting propagation to {host} using credential '{creds}'..." + '\033[0m')
    print("Propagation simulation complete.")

def simulate_update_screen():
    clear_screen()
    print_centered("Checking for updates to M.E.Doc...", bold=True)
    for pct in (0, 25, 50, 75, 100):
        print_centered(f"Update progress: {pct}%", bold=True)
        time.sleep(UPDATE_DELAY)
    print_centered("Update completed.", bold=True)
    time.sleep(UPDATE_DELAY)

def simulate_chkdscreen():
    clear_screen()
    lines = [
        "CHKDSK is verifying files (stage 1 of 3): 0 percent complete.",
        "CHKDSK is verifying files (stage 1 of 3): 33 percent complete.",
        "CHKDSK is verifying files (stage 2 of 3): 66 percent complete.",
        "CHKDSK is verifying files (stage 3 of 3): 100 percent complete.",
        "Windows has scanned the file system and found no problems."
    ]
    for line in lines:
        print_centered(line)
        time.sleep(1)
    time.sleep(1)

def simulate_reboot_and_ransom():
    clear_screen()
    RED = '\033[31m'
    RESET = '\033[0m'
    print(RED + "Ooops, your important files are encrypted." + RESET)
    print()
    width = shutil.get_terminal_size().columns
    print(RED + "-" * width + RESET)
    print(RED + "If you see this text, then your files are no longer accessible, because they have been encrypted." + RESET)
    print(RED + "Perhaps you are busy looking for a way to recover your files, but don't waste your time." + RESET)
    print(RED + "Nobody can recover your files without our decryption service." + RESET)
    print()
    print(RED + "We guarantee that you can recover all your files safely and easily." + RESET)
    print(RED + "All you need to do is submit the payment and purchase the decryption key." + RESET)
    print()
    print(RED + "Please follow the instructions:" + RESET)
    print()
    print(RED + "1.  Send $300 worth of Bitcoin to following address:" + RESET)
    print(RED + "    1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" + RESET)
    print()
    print(RED + "2.  Send your Bitcoin wallet ID and personal installation key to e-mail wowsmith123456@posteo.net." + RESET)
    print(RED + "    Your personal installation key:" + RESET)
    print(RED + "    5wFm3N-18q2pb-tforrH-MHi62X-6sr5AZ-3ufGTg-oKNFqB-Ys9j4N-jJrdrP-4pqY8i" + RESET)
    print()
    print(RED + "If you have already purchased your key, please enter it below." + RESET)
    print()
    print(RED + "Key:" + RESET)

def simulate_credential_theft():
    clear_screen()
    print_centered("Running Mimikatz… dumping credentials", bold=True)
    time.sleep(1.2)
    print_centered("Domain Admin => Administrator : P@ssw0rd!", bold=True)
    time.sleep(1.5)


def main():
    parser = argparse.ArgumentParser(description='Safe NotPetya Demo')
    parser.add_argument('--demo-recover', action='store_true', help='Show decryption recovery mode')
    args = parser.parse_args()

    if args.demo_recover:
        # Decrypt using stored key+iv
        key, iv = load_key_iv()
        print("[Loaded AES-128 key and IV for decryption]")
        decrypt_file(key, iv)
        return
    else:
        # Encrypt and save key+iv
        key, iv = generate_key_iv()
        save_key_iv(key, iv)
        simulate_update_screen()
        encrypt_file(key, iv)

        # simulate worm spread
        hosts = ['HostA', 'HostB', 'HostC']
        creds = 'Admin123!'
        print("2. Simulating worm propagation steps...")
        simulate_propagation(hosts, creds)
        
        simulate_credential_theft()
        simulate_reboot_and_ransom()

if __name__ == '__main__':
    main()
