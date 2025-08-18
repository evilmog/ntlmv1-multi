import argparse
import base64
import hashlib
import binascii
import json
from Crypto.Cipher import DES

def byte_dump(decoded_bytes):
    print(f"\n[+] Decoded {len(decoded_bytes)} bytes from base64:\n")
    for i, b in enumerate(decoded_bytes):
        print(f"Byte {i:02}: 0x{b:02x}")

def decode_and_validate_99(enc_99):
    if not enc_99.startswith("$99$"):
        raise ValueError("Invalid $99$ prefix")

    b64_data = enc_99[4:].strip().rstrip("=")
    b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
    raw = base64.b64decode(b64_data)

    if len(raw) != 26:
        raise ValueError(f"Expected 26 bytes, got {len(raw)}")

    byte_dump(raw)

    challenge = raw[0:8].hex()
    ct1 = raw[8:16].hex()
    ct2 = raw[16:24].hex()
    pt3 = raw[24:26].hex()

    print("\n[+] Decoded Fields:")
    print(f"CHALLENGE        : {challenge}")
    print(f"CT1              : {ct1}")
    print(f"CT2              : {ct2}")
    print(f"PT3 (K3 fragment): {pt3}")

    return {
        "source": "$99$",
        "client_challenge": challenge,
        "server_challenge": challenge,
        "challenge": challenge,
        "ct1": ct1,
        "ct2": ct2,
        "ct3": None,
        "pt1": None,
        "pt2": None,
        "pt3": pt3
    }

def recover_key_from_ct3(ct3_hex, challenge_hex, ess_hex=None):
    ct3_bytes = bytes.fromhex(ct3_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)

    if len(ct3_bytes) != 8 or len(challenge_bytes) != 8:
        raise ValueError("ct3 and challenge must be 8 bytes (16 hex chars) each")

    if ess_hex:
        ess_bytes = bytes.fromhex(ess_hex)
        if len(ess_bytes) != 24:
            raise ValueError("ESS must be 24 bytes (48 hex chars)")
        if ess_bytes[8:] == b'\x00' * 16:
            challenge_bytes = hashlib.md5(challenge_bytes + ess_bytes[:8]).digest()[:8]

    ct3_val = int.from_bytes(ct3_bytes, 'big')
    challenge_val = int.from_bytes(challenge_bytes, 'big')

    found_key = None
    for i in range(0x10000):
        nthash_bytes = [i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0]
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
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted = cipher.encrypt(challenge_bytes)
        if int.from_bytes(encrypted, 'big') == ct3_val:
            found_key = i
            break

    if found_key is None:
        return None

    return f"{found_key & 0xFF:02x}{(found_key >> 8) & 0xFF:02x}"

def parse_ntlmv1(ntlmv1_hash, show_pt3=False):
    hashsplit = ntlmv1_hash.strip().split(':')
    if len(hashsplit) < 6:
        raise ValueError("Invalid NTLMv1 hash format")

    user = hashsplit[0]
    domain = hashsplit[2]
    client_challenge = hashsplit[5]
    lmresp = hashsplit[3]
    ntresp = hashsplit[4]
    ct1 = ntresp[0:16]
    ct2 = ntresp[16:32]
    ct3 = ntresp[32:48]

    ess = None
    if lmresp[20:] == "0000000000000000000000000000":
        ess = lmresp
        combined = client_challenge + lmresp[:16]
        m = hashlib.md5()
        m.update(binascii.unhexlify(combined))
        srvchallenge = m.digest()[:8].hex()
        effective_challenge = srvchallenge
    else:
        srvchallenge = client_challenge
        effective_challenge = client_challenge

    data = {
        "source": "ntlmv1",
        "username": user,
        "domain": domain,
        "client_challenge": client_challenge,
        "server_challenge": srvchallenge,
        "challenge": effective_challenge,
        "lmresp": lmresp,
        "ntresp": ntresp,
        "ct1": ct1,
        "ct2": ct2,
        "ct3": ct3,
        "pt1": None,
        "pt2": None,
        "pt3": None
    }

    if show_pt3:
        pt3 = recover_key_from_ct3(ct3, client_challenge, ess)
        data["pt3"] = pt3
        print(f"\nPT3: {pt3 if pt3 else 'Not found'}\n")

    print("\n[+] NTLMv1 Parsed:")
    for field in ["username", "domain", "client_challenge", "server_challenge", "challenge", "ct1", "ct2", "ct3", "pt3"]:
        print(f"{field.upper():>20}: {data.get(field)}")

    return data

def main():
    parser = argparse.ArgumentParser(description="Unified NTLMv1 and $99$ parser with pt3 cracking")
    parser.add_argument("--99", dest="hash_99", help="Base64-encoded $99$ string (starting with $99$)")
    parser.add_argument("--ntlmv1", dest="ntlmv1_hash", help="Responder-style NTLMv1 hash")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--ct3", action="store_true", help="Recover pt3 (k3) via DES brute-force")
    args = parser.parse_args()

    output = {}
    if args.hash_99:
        output["$99$"] = decode_and_validate_99(args.hash_99)
    if args.ntlmv1_hash:
        output["ntlmv1"] = parse_ntlmv1(args.ntlmv1_hash, show_pt3=args.ct3)
    if args.json:
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
