#!/usr/bin/env python3

"""
A simplified script to decrypt Firefox passwords stored in the 'logins.json'
file, using the master_key from 'key4.db'.

This script is based on the original work by @lclevy but has been
refactored for clarity and simplicity, focusing only on modern Firefox versions
that use key4.db and logins.json.

Requirements:
- pycryptodome: pip install pycryptodome
- pyasn1:       pip install pyasn1

Author:
   https://github.com/Banaanhangwagen
License: MIT
"""

import json
import sqlite3
import sys
from base64 import b64decode
from hashlib import pbkdf2_hmac, sha1
from hmac import new as hmac_new
from pathlib import Path
from argparse import ArgumentParser

# PyCryptodome imports
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import unpad

# pyasn1 for parsing ASN.1 data structures
from pyasn1.codec.der import decoder as der_decoder

# This is the “Cryptographic Key Attribute ID” for the master key in nssPrivate.
# It's a hardcoded ID used by Firefox to identify the main private key.
CKA_ID = b'\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def decrypt_moz_3des(global_salt: bytes, master_password: bytes, entry_salt: bytes, encrypted_data: bytes) -> bytes:
    """
    Decrypts data using the legacy 3DES PBE algorithm used by NSS.

    This is based on the process described at:
    http://www.drh-consultancy.demon.co.uk/key3.html
    """
    # 1. Create a "Password Hash" (hp): SHA1(global_salt + master_password)
    hp = sha1(global_salt + master_password).digest()

    # 2. Create a "Password-Extended Salt" (pes): entry_salt padded to 20 bytes
    pes = entry_salt + b'\x00' * (20 - len(entry_salt))

    # 3. Create a "Salted Password Hash" (chp): SHA1(hp + entry_salt)
    chp = sha1(hp + entry_salt).digest()

    # 4. Derive the first part of the key (k1): HMAC-SHA1(chp, pes + entry_salt)
    k1 = hmac_new(chp, pes + entry_salt, sha1).digest()

    # 5. Derive an intermediate key (tk): HMAC-SHA1(chp, pes)
    tk = hmac_new(chp, pes, sha1).digest()

    # 6. Derive the second part of the key (k2): HMAC-SHA1(chp, tk + entry_salt)
    k2 = hmac_new(chp, tk + entry_salt, sha1).digest()

    # 7. The final key (k) is k1 + k2.
    k = k1 + k2

    # The 24-byte 3DES key is the first 24 bytes of k.
    # The 8-byte IV is the last 8 bytes of k.
    iv = k[24:32]  # This is incorrect, IV is last 8 bytes of k
    key = k[:24]   # Key is first 24 bytes

    # Correction from original script:
    iv = k[-8:] # IV is the *last* 8 bytes
    key = k[:24] # Key is the *first* 24 bytes

    # 8. Decrypt the data
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(encrypted_data)


def decrypt_pbe(decoded_item: tuple, master_password: bytes, global_salt: bytes) -> tuple[bytes, str]:
    """
    Decrypts an ASN.1 PBE (Password-Based Encryption) item.
    Firefox 75+ uses PBES2 (AES), while older versions used 3DES.
    This function supports both.
    """
    # The PBE algorithm OID (Object Identifier) tells us which method to use.
    pbe_algo_oid = str(decoded_item[0][0][0])

    if pbe_algo_oid == '1.2.840.113549.1.12.5.1.3':
        # --- Legacy 3DES PBE ---
        # OID: pbeWithSha1AndTripleDES-CBC
        entry_salt = decoded_item[0][0][1][0].asOctets()
        cipher_text = decoded_item[0][1].asOctets()

        clear_text = decrypt_moz_3des(global_salt, master_password, entry_salt, cipher_text)
        return clear_text, pbe_algo_oid

    elif pbe_algo_oid == '1.2.840.113549.1.5.13':
        # --- Modern PBES2 (AES) ---
        # OID: pkcs5 pbes2

        # 1. Extract PBKDF2 parameters
        # These are nested deep in the ASN.1 structure.
        pbkdf2_params = decoded_item[0][0][1][0][1]
        entry_salt = pbkdf2_params[0].asOctets()
        iteration_count = int(pbkdf2_params[1])
        key_length = int(pbkdf2_params[2])  # Should be 32 bytes (256 bits)

        # 2. Extract AES-CBC parameters
        aes_params = decoded_item[0][0][1][1]
        # The IV is hardcoded with a 2-byte prefix (0x04, 0x0e) by NSS
        iv_prefix = b'\x04\x0e'
        iv_suffix = aes_params[1].asOctets()
        iv = iv_prefix + iv_suffix

        # 3. Extract the encrypted data
        cipher_text = decoded_item[0][1].asOctets()

        # 4. Derive the decryption key
        # First, create an intermediate key: SHA1(global_salt + master_password)
        k_intermediate = sha1(global_salt + master_password).digest()

        # Now, use PBKDF2 with the intermediate key as the "password"
        key = pbkdf2_hmac(
            'sha256',
            k_intermediate,
            entry_salt,
            iteration_count,
            dklen=key_length
        )

        # 5. Decrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        clear_text = cipher.decrypt(cipher_text)
        return clear_text, pbe_algo_oid

    else:
        raise Exception(f"Unknown PBE algorithm: {pbe_algo_oid}")


def get_master_key(db_path: Path, master_password: str) -> bytes:

    master_password_bytes = master_password.encode('utf-8')

    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()

        # --- 1. Verify Master Password ---
        # 'password' row in metadata contains the password-check data
        c.execute("SELECT item1, item2 FROM metadata WHERE id = 'password';")
        row = c.fetchone()
        if not row:
            raise Exception("Could not find password-check data in key4.db.")
        print(f"[INFO] - Reading key4-db: verifying master_password")

        global_salt = row[0]  # item1
        # print(f"Global salt from 'password'-row:\t\t\t", global_salt.hex())
        encrypted_check_data = row[1]  # item2
        # print(f"Encrypted_check_data from 'password'-row:\t", encrypted_check_data.hex())


        # Decode the ASN.1 structure of the password-check data
        decoded_check = der_decoder.decode(encrypted_check_data)
        # print(f"Decoded_check_data:\t\t\t\t\t\t\t", decoded_check)

        # Decrypt it
        clear_text, _ = decrypt_pbe(decoded_check, master_password_bytes, global_salt)
        # print(f"Master password:\t\t\t\t\t\t\t", master_password_bytes)
        # print(f"Clear text:\t\t\t\t\t\t\t\t\t", clear_text)

        # Check if decryption was successful
        if clear_text != b'password-check\x02\x02':
            raise Exception("Master password is incorrect. Did you provide the correct password?")

        print("\t[!] Master password is correct.")

        # --- 2. Decrypt the Master Key ---
        # The key is in the 'nssPrivate' table, identified by CKA_ID
        print(f"[INFO] - Reading key4-db: obtaining master_key")

        c.execute("SELECT a11, a102 FROM nssPrivate;")
        master_key_data = None
        for row in c:
            if row[1] == CKA_ID:  # a102 is CKA_ID
                master_key_data = row[0]  # a11 is encrypted master_key
                break

        if not master_key_data:
            raise Exception("Could not find master key in nssPrivate table.")

        # Decode and decrypt the master key
        decoded_key = der_decoder.decode(master_key_data)
        # print(f"Raw encrypted master_key:\t\t\t\t\t", master_key_data.hex())
        # print(f"Decoded master_key:\t\t\t\t\t\t\t", decoded_key)

        # The decrypted result *is* the 24-byte 3DES key used for logins
        final_key, algo = decrypt_pbe(decoded_key, master_password_bytes, global_salt)

        # print(f"Mentioned algo ID:\t\t\t\t\t\t\t {algo}")
        print(f"\t[!] Decrypted master_key :", final_key.hex())

        return final_key


def get_logins(logins_path: Path) -> list:
    """
    Parses the logins.json file and extracts the encrypted data.
    """
    try:
        data = json.loads(logins_path.read_text())
    except FileNotFoundError:
        print(f"Error: Could not find '{logins_path.name}'.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not parse '{logins_path.name}'.")
        sys.exit(1)

    if 'logins' not in data:
        return []

    logins = []
    for entry in data['logins']:
        # We just b64decode. The ASN.1 decoding will be done later
        logins.append({
            "hostname": entry['hostname'],
            "username_data": b64decode(entry['encryptedUsername']),
            "password_data": b64decode(entry['encryptedPassword']),
        })
    return logins


def decrypt_login(login_data_bytes: bytes, key: bytes) -> str:
    """
oidValues = {b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',
             b'2a864886f70d0307': '1.2.840.113549.3.7 des-ede3-cbc',
             b'2a864886f70d010101': '1.2.840.113549.1.1.1 pkcs-1',
             b'2a864886f70d01050d': '1.2.840.113549.1.5.13 pkcs5 pbes2',
             b'2a864886f70d01050c': '1.2.840.113549.1.5.12 pkcs5 PBKDF2',
             b'2a864886f70d0209': '1.2.840.113549.2.9 hmacWithSHA256',
             b'60864801650304012a': '2.16.840.1.101.3.4.1.42 aes256-CBC'
             }
    """
    # 1. Decode the ASN.1 structure from the raw bytes
    login_data = der_decoder.decode(login_data_bytes)

    # 2. Extract IV and ciphertext
    key_id = login_data[0][0].asOctets()
    algo_oid = str(login_data[0][1][0])
    iv = login_data[0][1][1].asOctets()
    ciphertext = login_data[0][2].asOctets()
    # version = login_data[0][1][0]
    # print(f"    [Debug] key_id:     {key_id.hex()}")
    # print(f"    [Debug] Version:    {algo_oid}")
    # print(f"    [Debug] IV:         {iv.hex()}")
    # print(f"    [Debug] Ciphertext: {ciphertext.hex()}")

    # 3. Decrypt
    if algo_oid == '1.2.840.113549.3.7' : # or algo_oid == '1.2.840.113549.1.12.5.1.3' or algo_oid == '1.2.840.113549.1.5.13':  # 3DES-CBC
        # Use first 24 bytes of master key
        decryption_key = key[:24]
        cipher = DES3.new(decryption_key, DES3.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), DES3.block_size)

    elif algo_oid == '2.16.840.1.101.3.4.1.42':  # AES256-CBC
        # Use first 32 bytes of master key
        decryption_key = key[:32]
        cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    else:
        raise Exception(f"Unknown login encryption algorithm: {algo_oid}")

    # 4. Decode from bytes to string
    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
            return repr(decrypted_bytes)

def main():
    # --- 1. Parse Arguments ---
    parser = ArgumentParser(description="Decrypt Firefox passwords from key4.db and logins.json")
    parser.add_argument("-d", "--dir", dest="directory",
                        required=True,
                        help="Path to the Firefox profile directory")
    parser.add_argument("-p", "--password", dest="master_password",
                        help="The master password (if any)", default='')

    args = parser.parse_args()

    profile_dir = Path(args.directory)
    key_db_path = profile_dir / 'key4.db'
    logins_json_path = profile_dir / 'logins.json'

    if not key_db_path.exists():
        print(f"Error: 'key4.db' not found in '{profile_dir}'")
        print("This script only supports key4.db (Firefox 58+).")
        sys.exit(1)

    if not logins_json_path.exists():
        print(f"Error: 'logins.json' not found in '{profile_dir}'")
        sys.exit(1)

    # --- 2. Get the Master Key ---
    try:
        master_key = get_master_key(key_db_path, args.master_password)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # --- 3. Get Encrypted Logins ---
    logins = get_logins(logins_json_path)
    if not logins:
        print("No logins found in logins.json.")
        sys.exit(0)

    print(f"\n[INFO] - Decrypted {len(logins)} logins")

    # --- 4. Decrypt and Print ---
    for entry in logins:
        try:
            username = decrypt_login(entry['username_data'], master_key)
            password = decrypt_login(entry['password_data'], master_key)

            print(f"\n  URL: {entry['hostname']}")
            print(f"  User: {username}")
            print(f"  Pass: {password}")

        except Exception as e:
            print(f"\n  [!] Failed to decrypt entry for {entry['hostname']}: {e}")

if __name__ == "__main__":
    main()
