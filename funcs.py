import hashlib,binascii

def f_ntlmsplit( ntlm ):
  ntlm_1 = ntlm[0:14]
  ntlm_2 = ntlm[14:28]
  return [ntlm_1, ntlm_2]

def f_ntlm_to_bin( ntlm_part ):
  ntlm_part_int = int(ntlm_part, 16)
  ntlm_part_bin = format(ntlm_part_int, '0>56b')
  ntlm_bin_key1 = ntlm_part_bin[0:7]
  ntlm_bin_key2 = ntlm_part_bin[7:14]
  ntlm_bin_key3 = ntlm_part_bin[14:21]
  ntlm_bin_key4 = ntlm_part_bin[21:28]
  ntlm_bin_key5 = ntlm_part_bin[28:35]
  ntlm_bin_key6 = ntlm_part_bin[35:42]
  ntlm_bin_key7 = ntlm_part_bin[42:49]
  ntlm_bin_key8 = ntlm_part_bin[49:56]
  return [ntlm_bin_key1, ntlm_bin_key2, ntlm_bin_key3, ntlm_bin_key4, ntlm_bin_key5, ntlm_bin_key6, ntlm_bin_key7, ntlm_bin_key8]

def f_ntlm_des_part ( ntlm_key ):
  ntlm_part1 = int(ntlm_key[0])
  ntlm_part2 = int(ntlm_key[1])
  ntlm_part3 = int(ntlm_key[2])
  ntlm_part4 = int(ntlm_key[3])
  ntlm_part5 = int(ntlm_key[4])
  ntlm_part6 = int(ntlm_key[5])
  ntlm_part7 = int(ntlm_key[6])
  ntlm_parity = (int(ntlm_key[0])+int(ntlm_key[1])+int(ntlm_key[2])+int(ntlm_key[3])+int(ntlm_key[4])+int(ntlm_key[5])+int(ntlm_key[6]))
  if int(ntlm_parity % 2 == 0):
    parity=int(1)
  else:
    parity=int(0)
  des_part = str('{:02x}'.format(int(str(ntlm_key)+str(parity), 2)))
  return des_part

def f_ntlm_des ( ntlm_key ):
  ntlm_keys = f_ntlm_to_bin(ntlm_key)
  des_key1 = str(f_ntlm_des_part(ntlm_keys[0]))
  des_key2 = str(f_ntlm_des_part(ntlm_keys[1]))
  des_key3 = str(f_ntlm_des_part(ntlm_keys[2]))
  des_key4 = str(f_ntlm_des_part(ntlm_keys[3]))
  des_key5 = str(f_ntlm_des_part(ntlm_keys[4]))
  des_key6 = str(f_ntlm_des_part(ntlm_keys[5]))
  des_key7 = str(f_ntlm_des_part(ntlm_keys[6]))
  des_key8 = str(f_ntlm_des_part(ntlm_keys[7]))
  return (des_key1+des_key2+des_key3+des_key4+des_key5+des_key6+des_key7)
