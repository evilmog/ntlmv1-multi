import argparse
import base64
import hashlib
import binascii
import json
from Crypto.Cipher import DES


def des_to_ntlm_slice(deskey_hex):
    deskey = bytes.fromhex(deskey_hex)
    bits = ''.join([f"{byte:08b}" for byte in deskey])
    stripped = ''.join([bits[i:i+7] for i in range(0, 64, 8)])
    ntlm_bytes = int(stripped, 2).to_bytes(7, 'big')
    return ntlm_bytes.hex()


def decode_and_validate_99(enc_99):
    if not enc_99.startswith("$99$"):
        raise ValueError("Invalid $99$ prefix")
    b64_data = enc_99[4:].strip().rstrip("=")
    b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
    raw = base64.b64decode(b64_data)
    if len(raw) != 26:
        raise ValueError(f"Expected 26 bytes, got {len(raw)}")
    return {
        "source": "$99$",
        "client_challenge": raw[0:8].hex(),
        "server_challenge": raw[0:8].hex(),
        "challenge": raw[0:8].hex(),
        "ct1": raw[8:16].hex(),
        "ct2": raw[16:24].hex(),
        "pt3": raw[24:26].hex(),
        "ct3": None,
        "pt1": None,
        "pt2": None,
    }


def des_encrypt_block(key8_hex, challenge_hex):
    if len(key8_hex) != 16 or len(challenge_hex) != 16:
        return None
    key_bytes = bytes.fromhex(key8_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    return cipher.encrypt(challenge_bytes).hex()


def recover_key_from_ct3(ct3_hex, challenge_hex, ess_hex=None):
    ct3_bytes = bytes.fromhex(ct3_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)

    if len(ct3_bytes) != 8 or len(challenge_bytes) != 8:
        raise ValueError("ct3 and challenge must be 8 bytes (16 hex chars) each")

    if ess_hex:
        ess_bytes = bytes.fromhex(ess_hex)
        if len(ess_bytes) == 24 and ess_bytes[8:] == b'\x00' * 16:
            challenge_bytes = hashlib.md5(challenge_bytes + ess_bytes[:8]).digest()[:8]

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
        if encrypted == ct3_bytes:
            return '{:02x}{:02x}'.format(i & 0xFF, (i >> 8) & 0xFF)

    return None


def parse_ntlmv1(ntlmv1_hash, key1=None, key2=None, show_pt3=False, json_mode=False):
    fields = ntlmv1_hash.strip().split(':')
    if len(fields) < 6:
        raise ValueError("Invalid NTLMv1 format")
    user, domain, lmresp, ntresp, challenge = fields[0], fields[2], fields[3], fields[4], fields[5]
    ct1, ct2, ct3 = ntresp[0:16], ntresp[16:32], ntresp[32:48]

    ess = None
    if lmresp[20:] == "0000000000000000000000000000":
        ess = lmresp
        m = hashlib.md5()
        m.update(binascii.unhexlify(challenge + lmresp[:16]))
        challenge = m.digest()[:8].hex()

    data = {
        "source": "ntlmv1",
        "username": user,
        "domain": domain,
        "client_challenge": fields[5],
        "server_challenge": challenge,
        "challenge": challenge,
        "lmresp": lmresp,
        "ntresp": ntresp,
        "ct1": ct1,
        "ct2": ct2,
        "ct3": ct3,
        "pt1": None,
        "pt2": None,
        "pt3": None,
        "ntlm": None
    }

    if key1 and len(key1) == 16:
        encrypted1 = des_encrypt_block(key1, challenge)
        if encrypted1 and encrypted1.lower() == ct1.lower():
            pt1 = des_to_ntlm_slice(key1)
            data["pt1"] = pt1

    if key2 and len(key2) == 16:
        encrypted2 = des_encrypt_block(key2, challenge)
        if encrypted2 and encrypted2.lower() == ct2.lower():
            pt2 = des_to_ntlm_slice(key2)
            data["pt2"] = pt2

    if show_pt3 or (data["pt1"] and data["pt2"]):
        pt3 = recover_key_from_ct3(ct3, challenge, ess)
        data["pt3"] = pt3

    if data["pt1"] and data["pt2"] and data["pt3"]:
        data["ntlm"] = data["pt1"] + data["pt2"] + data["pt3"]

    if not json_mode:
        print("\n[+] NTLMv1 Parsed:")
        for field in ["username", "domain", "challenge", "ct1", "ct2", "ct3", "pt1", "pt2", "pt3", "ntlm"]:
            print(f"{field.upper():>12}: {data.get(field)}")
    return data


def ntlmv1_to_99(parsed):
    try:
        challenge = bytes.fromhex(parsed["challenge"])
        ct1 = bytes.fromhex(parsed["ct1"])
        ct2 = bytes.fromhex(parsed["ct2"])
        pt3 = bytes.fromhex(parsed["pt3"])  # pt3 is already recovered via parse_ntlmv1()

        raw = challenge + ct1 + ct2 + pt3
        b64 = base64.b64encode(raw).decode().rstrip("=")
        return f"$99${b64}"
    except Exception as e:
        print(f"[-] Failed to convert to $99$: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="NTLMv1/$99$ parser with correct DES key handling and CT3 recovery.")
    parser.add_argument("--ntlmv1", help="NTLMv1 hash (Responder format)")
    parser.add_argument("--99", dest="hash_99", help="$99$ style base64 blob")
    parser.add_argument("--key1", help="16-char DES key hex for CT1")
    parser.add_argument("--key2", help="16-char DES key hex for CT2")
    parser.add_argument("--ct3", action="store_true", help="Brute-force CT3 key")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--to99", action="store_true", help="Convert NTLMv1 hash to $99$ format")
    args = parser.parse_args()

    output = {}
    if args.hash_99:
        data_99 = decode_and_validate_99(args.hash_99)

        if args.key1:
            encrypted1 = des_encrypt_block(args.key1, data_99["challenge"])
            if encrypted1 and encrypted1.lower() == data_99["ct1"].lower():
                data_99["pt1"] = des_to_ntlm_slice(args.key1)

        if args.key2:
            encrypted2 = des_encrypt_block(args.key2, data_99["challenge"])
            if encrypted2 and encrypted2.lower() == data_99["ct2"].lower():
                data_99["pt2"] = des_to_ntlm_slice(args.key2)

        # Optional: compute full NTLM hash if all parts are present
        if data_99.get("pt1") and data_99.get("pt2") and data_99.get("pt3"):
            data_99["ntlm"] = data_99["pt1"] + data_99["pt2"] + data_99["pt3"]

        output["$99$"] = data_99

        if not args.json:
            print("\n[+] $99$ Parsed:")
            for field in ["client_challenge", "ct1", "ct2", "ct3", "pt1", "pt2", "pt3", "ntlm"]:
                print(f"{field.upper():>20}: {data_99.get(field)}")
                
    if args.ntlmv1:
        output["ntlmv1"] = parse_ntlmv1(
            args.ntlmv1,
            key1=args.key1,
            key2=args.key2,
            show_pt3=args.ct3,
            json_mode=args.json
        )
    if args.to99:
        if not args.ntlmv1:
            print("[-] --to99 requires --ntlmv1")
        else:
            # Force pt3 recovery during parse
            parsed = parse_ntlmv1(
                args.ntlmv1,
                key1=args.key1,
                key2=args.key2,
                show_pt3=True,
                json_mode=args.json
            )
            result = ntlmv1_to_99(parsed)
            if args.json:
                output = {
                    "ntlmv1": parsed,
                    "$99$": result
                }
                print(json.dumps(output, indent=2))
            else:
                print(f"[+] Converted to $99$:\n{result}")
        return  # Skip rest of the logic

    if args.json:
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
