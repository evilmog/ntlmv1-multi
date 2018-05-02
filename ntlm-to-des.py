from __future__ import print_function
import hashlib,binascii
import argparse
from funcs import *

parser = argparse.ArgumentParser()
parser.add_argument('--ntlm', help='NTLM Hash', required=True)
args = parser.parse_args()

ntlm_split = f_ntlmsplit(args.ntlm)
f_ntlm_des_1 = f_ntlm_des(ntlm_split[0])
f_ntlm_des_2 = f_ntlm_des(ntlm_split[1])

print("DESKEY1: " + f_ntlm_des_1)
print("DESKEY2: " + f_ntlm_des_2+"\n")

print("echo " + f_ntlm_des_1 + ">>des.cand")
print("echo " + f_ntlm_des_2 + ">>des.cand")
