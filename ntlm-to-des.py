import hashlib,binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--ntlm', help='NTLM Hash', required=True)
args = parser.parse_args()

ntlm = args.ntlm

ntlm_1 = ntlm[0:14]
ntlm_2 = ntlm[14:28]
ntlm_1_int = int(ntlm_1, 16)
ntlm_2_int = int(ntlm_2, 16)

ntlm_1_bin = format(ntlm_1_int, '0>56b')
ntlm_2_bin = format(ntlm_2_int, '0>56b')

ntlm_1_bin_key1 = ntlm_1_bin[0:7]
ntlm_1_bin_key2 = ntlm_1_bin[7:14]
ntlm_1_bin_key3 = ntlm_1_bin[14:21]
ntlm_1_bin_key4 = ntlm_1_bin[21:28]
ntlm_1_bin_key5 = ntlm_1_bin[28:35]
ntlm_1_bin_key6 = ntlm_1_bin[35:42]
ntlm_1_bin_key7 = ntlm_1_bin[42:49]
ntlm_1_bin_key8 = ntlm_1_bin[49:56]

ntlm_2_bin_key1 = ntlm_2_bin[0:7]
ntlm_2_bin_key2 = ntlm_2_bin[7:14]
ntlm_2_bin_key3 = ntlm_2_bin[14:21]
ntlm_2_bin_key4 = ntlm_2_bin[21:28]
ntlm_2_bin_key5 = ntlm_2_bin[28:35]
ntlm_2_bin_key6 = ntlm_2_bin[35:42]
ntlm_2_bin_key7 = ntlm_2_bin[42:49]
ntlm_2_bin_key8 = ntlm_2_bin[49:56]

# ((int('1000101', 2) % 2) ^ 1)
ntlm_1_bin_key1_p = str(((int(ntlm_1_bin_key1, 2) % 2) ^ 1))
ntlm_1_bin_key2_p = str(((int(ntlm_1_bin_key2, 2) % 2) ^ 1))
ntlm_1_bin_key3_p = str(((int(ntlm_1_bin_key3, 2) % 2) ^ 1))
ntlm_1_bin_key4_p = str(((int(ntlm_1_bin_key4, 2) % 2) ^ 1))
ntlm_1_bin_key5_p = str(((int(ntlm_1_bin_key5, 2) % 2) ^ 1))
ntlm_1_bin_key6_p = str(((int(ntlm_1_bin_key6, 2) % 2) ^ 1))
ntlm_1_bin_key7_p = str(((int(ntlm_1_bin_key7, 2) % 2) ^ 1))
ntlm_1_bin_key8_p = str(((int(ntlm_1_bin_key8, 2) % 2) ^ 1))

ntlm_2_bin_key1_p = str(((int(ntlm_2_bin_key1, 2) % 2) ^ 1))
ntlm_2_bin_key2_p = str(((int(ntlm_2_bin_key2, 2) % 2) ^ 1))
ntlm_2_bin_key3_p = str(((int(ntlm_2_bin_key3, 2) % 2) ^ 1))
ntlm_2_bin_key4_p = str(((int(ntlm_2_bin_key4, 2) % 2) ^ 1))
ntlm_2_bin_key5_p = str(((int(ntlm_2_bin_key5, 2) % 2) ^ 1))
ntlm_2_bin_key6_p = str(((int(ntlm_2_bin_key6, 2) % 2) ^ 1))
ntlm_2_bin_key7_p = str(((int(ntlm_2_bin_key7, 2) % 2) ^ 1))
ntlm_2_bin_key8_p = str(((int(ntlm_2_bin_key8, 2) % 2) ^ 1))

des_1_key1 = str(hex(int(ntlm_1_bin_key1+ntlm_1_bin_key1_p, 2)))[2:4]
des_1_key2 = str(hex(int(ntlm_1_bin_key2+ntlm_1_bin_key2_p, 2)))[2:4]
des_1_key3 = str(hex(int(ntlm_1_bin_key3+ntlm_1_bin_key3_p, 2)))[2:4]
des_1_key4 = str(hex(int(ntlm_1_bin_key4+ntlm_1_bin_key4_p, 2)))[2:4]
des_1_key5 = str(hex(int(ntlm_1_bin_key5+ntlm_1_bin_key5_p, 2)))[2:4]
des_1_key6 = str(hex(int(ntlm_1_bin_key6+ntlm_1_bin_key6_p, 2)))[2:4]
des_1_key7 = str(hex(int(ntlm_1_bin_key7+ntlm_1_bin_key7_p, 2)))[2:4]
des_1_key8 = str(hex(int(ntlm_1_bin_key8+ntlm_1_bin_key8_p, 2)))[2:4]

des_2_key1 = str(hex(int(ntlm_2_bin_key1+ntlm_2_bin_key1_p, 2)))[2:4]
des_2_key2 = str(hex(int(ntlm_2_bin_key2+ntlm_2_bin_key2_p, 2)))[2:4]
des_2_key3 = str(hex(int(ntlm_2_bin_key3+ntlm_2_bin_key3_p, 2)))[2:4]
des_2_key4 = str(hex(int(ntlm_2_bin_key4+ntlm_2_bin_key4_p, 2)))[2:4]
des_2_key5 = str(hex(int(ntlm_2_bin_key5+ntlm_2_bin_key5_p, 2)))[2:4]
des_2_key6 = str(hex(int(ntlm_2_bin_key6+ntlm_2_bin_key6_p, 2)))[2:4]
des_2_key7 = str(hex(int(ntlm_2_bin_key7+ntlm_2_bin_key7_p, 2)))[2:4]
des_2_key8 = str(hex(int(ntlm_2_bin_key8+ntlm_2_bin_key8_p, 2)))[2:4]

print "DESKEY1: " + des_1_key1+des_1_key2+des_1_key3+des_1_key4+des_1_key5+des_1_key6+des_1_key7+des_1_key8
print "DESKEY2: " + des_2_key1+des_2_key2+des_2_key3+des_2_key4+des_2_key5+des_2_key6+des_2_key7+des_2_key8
