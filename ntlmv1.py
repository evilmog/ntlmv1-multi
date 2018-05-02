from __future__ import print_function
import hashlib,binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--noess', help='NTLMv1 Hash in responder format', required=True)
args = parser.parse_args()
# evilmog::DUSTIN-5AA37877:E343946E455EFC72746CF587C42022982F85252CC731BB25:51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C:1122334455667788
hashsplit = args.noess.split(':')
challenge = hashsplit[5]
combined = hashsplit[4]
ct1 = combined[0:16]
ct2 = combined[16:32]
ct3 = combined[32:48]

print("Hashfield Split:")
print(str(hashsplit) + "\n")

print("Hostname: " + hashsplit[2])
print("Username: " + hashsplit[0])
print("Challenge: " + challenge)
print("Combined: " + combined)
print("CT1: " + ct1)
print("CT2: " + ct2)
print("CT3: " + ct3 + "\n")

print("To Calculate final 4 characters of NTLM hash use:")
print("./ct3_to_ntlm.bin " + ct3 + " " + challenge + "\n")
#./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c

print("To crack with hashcat create a file with the following contents:")
print(ct1 + ":" + challenge)
print(ct2 + ":" + challenge + "\n")

print("To crack with hashcat:")
print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1")

