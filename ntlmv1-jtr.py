from __future__ import print_function
import hashlib,binascii
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--jtr', help='NTLMv1 Hash in JTR format', required=True)
args = parser.parse_args()

hashsplit = args.jtr.split('$')
#$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233

if hashsplit[0] == "":
  if hashsplit[1] == "NETNTLM":
    challenge = hashsplit[2]
    combined = hashsplit[3]
    ct1 = ct1 = combined[0:16]
    ct2 = combined[16:32]
    ct3 = combined[32:48]

    print("Hashfield Split:")
    print(str(hashsplit) + "\n")
    print("Challenge: " + challenge)
    print("Combined: " + combined)
    print("CT1: " + ct1)
    print("CT2: " + ct2)
    print("CT3: " + ct3 + "\n")

    print("To Calculate final 4 characters of NTLM hash use:")
    print("./ct3_to_ntlm.bin " + ct3 + " " + challenge + "\n")

    print("To crack with hashcat create a file with the following contents:")
    print(ct1 + ":" + challenge)
    print(ct2 + ":" + challenge + "\n")

    print("To crack with hashcat:")
    print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1")

    sys.exit()

print("Incorrect Syntax, usage: python ntlmv1-jtr.py --jtr '$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233'")
