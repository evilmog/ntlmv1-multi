import hashlib,binascii
import argparse
from funcs import *

parser = argparse.ArgumentParser()
parser.add_argument('--ntlm', help='NTLM Hash', required=False)
parser.add_argument('--bulk', help='file for bulk import', required=False)
parser.add_argument('--tail', help='output bulk with final piece of ntlm appended, eg DESKEY:aaaa for easy grep', required=False)
parser.add_argument('--plain', help='file with plaintext that needs to be converted to ntlm and des', required=False)

args = parser.parse_args()

if args.ntlm is not None:
  ntlm_split = f_ntlmsplit(args.ntlm)
  f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
  f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])

  print "DESKEY1: " + f_ntlm_des_1
  print "DESKEY2: " + f_ntlm_des_2+"\n"

  print "echo \"$HEX[" + f_ntlm_des_1 + "]\">>des.cand"
  print "echo \"$HEX[" + f_ntlm_des_2 + "]\">>des.cand"

if args.bulk is not None:
  try:
    with open(args.bulk) as fp:
      for cnt, line in enumerate(fp):
        ntlm_split = f_ntlmsplit(line.rstrip())
        f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
        f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])
        if args.tail is None:
          print f_ntlm_des_1
          print f_ntlm_des_2
        else:
          print "$HEX[" + f_ntlm_des_1 + "]:" + ntlm_split[2].lower()
          print "$HEX[" + f_ntlm_des_2 + "]:" + ntlm_split[2].lower()
  finally:
    fp.close()

if args.plain is not None:
  try:
    with open(args.plain) as fp:
      for cnt, line in enumerate(fp):
        hash = hashlib.new('md4', line.rstrip().encode('utf-16le')).digest()
        ntlm_hash = binascii.hexlify(hash)
        print ntlm_hash
        ntlm_split = f_ntlmsplit(ntlm_hash)
        print ntlm_split
        f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
        f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])
        if args.tail is None:
          print f_ntlm_des_1
          print f_ntlm_des_2
        else:
          print "$HEX[" + f_ntlm_des_1 + "]:" + ntlm_split[2].lower()
          print "$HEX[" + f_ntlm_des_2 + "]:" + ntlm_split[2].lower()
  finally:
    fp.close()
