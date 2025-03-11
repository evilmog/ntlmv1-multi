# /*
# * Author.......: Dustin Heywood <dustin.heywood@gmail.com>
# * Used C code stolen from .......: Jens Steube <jens.steube@gmail.com>
# * Thus this code is under the same license
# * License.....: MIT
# *
# * Most of the C code taken from hashcat use for the python port
# */

import argparse
from Crypto.Cipher import DES
import hashlib

def recover_key_from_ct3(ct3_hex, challenge_hex, ess_hex=None):
    # Convert hex inputs to bytes
    ct3_bytes = bytes.fromhex(ct3_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)

    if len(ct3_bytes) != 8 or len(challenge_bytes) != 8:
        raise ValueError("ct3 and salt must be 8 bytes (16 hex chars) each")

    # Convert bytes to integer representation
    ct3_val = int.from_bytes(ct3_bytes, 'big')
    challenge_val = int.from_bytes(challenge_bytes, 'big')

    # Handle ESS case using fast MD5 hash
    if ess_hex:
        ess_bytes = bytes.fromhex(ess_hex)
        if len(ess_bytes) != 24:
            raise ValueError("ESS must be 24 bytes (48 hex chars)")
        if ess_bytes[8:] == b'\x00' * 16:
            challenge_bytes = hashlib.md5(challenge_bytes + ess_bytes[:8]).digest()[:8]
            challenge_val = int.from_bytes(challenge_bytes, 'big')

    # **Optimized DES brute-force loop**
    found_key = None
    for i in range(0x10000):  # 16-bit key space
        # **Optimized 7-byte to 8-byte DES key transformation**
        nthash_bytes = [
            i & 0xFF,
            (i >> 8) & 0xFF,
            0, 0, 0, 0, 0
        ]
        key_bytes = bytes([
            nthash_bytes[0] | 1,
            ((nthash_bytes[0] << 7) | (nthash_bytes[1] >> 1)) & 0xFF | 1,
            ((nthash_bytes[1] << 6) | (nthash_bytes[2] >> 2)) & 0xFF | 1,
            ((nthash_bytes[2] << 5) | (nthash_bytes[3] >> 3)) & 0xFF | 1,
            ((nthash_bytes[3] << 4) | (nthash_bytes[4] >> 4)) & 0xFF | 1,
            ((nthash_bytes[4] << 3) | (nthash_bytes[5] >> 5)) & 0xFF | 1,
            ((nthash_bytes[5] << 2) | (nthash_bytes[6] >> 6)) & 0xFF | 1,
            ((nthash_bytes[6] << 1)) & 0xFF | 1
        ])

        # **Use PyCryptodome for fast DES encryption**
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted = cipher.encrypt(challenge_bytes)

        # **Fast integer comparison instead of byte-by-byte check**
        if int.from_bytes(encrypted, 'big') == ct3_val:
            found_key = i
            break

    if found_key is None:
        return None  # Key not found

    # **Return key in correct format (low-order byte first, as in C output)**
    return f"{found_key & 0xFF:02x}{(found_key >> 8) & 0xFF:02x}"

def main():
    parser = argparse.ArgumentParser(description="Recover a DES key from ct3 and salt values.")
    parser.add_argument("ct3", type=str, help="8-byte ciphertext (16 hex chars)")
    parser.add_argument("salt", type=str, help="8-byte salt value (16 hex chars)")
    parser.add_argument("ess", type=str, nargs='?', default=None, help="24-byte ESS value (48 hex chars, optional)")
    
    args = parser.parse_args()
    
    key = recover_key_from_ct3(args.ct3, args.salt, args.ess)
    
    if key:
        print(f"Recovered key: {key}")
    else:
        print("Key not found")

if __name__ == "__main__":
    main()

