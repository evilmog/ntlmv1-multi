import hashlib,binascii
import argparse
from funcs import *

parser = argparse.ArgumentParser()
parser.add_argument('--ntlm', help='NTLM Hash', required=True)
parser.add_argument('--bulk', help='file for bulk import', required=False)
parser.add_argument('--tail', help='output bulk with final piece of ntlm appended, eg DESKEY:aaaa for easy grep', required=False)
args = parser.parse_args()

if args.bulk == None:
  ntlm_split = f_ntlmsplit(args.ntlm)
  f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
  f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])

  print "DESKEY1: " + f_ntlm_des_1
  print "DESKEY2: " + f_ntlm_des_2+"\n"

  print "echo " + f_ntlm_des_1 + ">>des.cand"
  print "echo " + f_ntlm_des_2 + ">>des.cand"

if args.bulk is not None:
  try:
    with open(args.bulk) as fp:
      for cnt, line in enumerate(fp):
        #print("Line {}: {}".format(cnt, line.rstrip()))
        ntlm_split = f_ntlmsplit(line.rstrip())
        f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
        f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])
        if args.tail is None:
          print f_ntlm_des_1
          print f_ntlm_des_2
        else:
          print f_ntlm_des_1 + ":" + ntlm_split[2].lower()
          print f_ntlm_des_2 + ":" + ntlm_split[2].lower()
  finally:
    fp.close()


