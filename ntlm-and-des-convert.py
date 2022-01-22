#! /usr/bin/env python3
r''' 
	Copyright 2022 Photubias(c)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        File name ntlm_to_des.py
        written by tijl[dot]deneut[at]howest[dot]be based on the good work at https://github.com/evilmog/ntlmv1-multi

        This script will convert NetNTLMv1 cracked DES keys to the NTLM hash (first 14 out of 16 bytes)
        or vice versa: convert an NTLM hash to the corresponding NetNTLMv1 DES keys
'''

import sys, os

def sNTLMPartToDES(sNTLMpart):
    ## Turn the 7 byte ntlm part hex string into 56bits binary string
    sBinaryNTLMPart = bin(int(sNTLMpart, 16))[2:].zfill(56)
    ## Walk over the bits per 7 bits to add a '1' in between
    sNewBinary = ''
    for i in range(0,56,7): 
        sNewBinary += sBinaryNTLMPart[i:i+7]
        sNewBinary += '1'
    ## Convert the new 64 bits back to a Hex String
    sDESKey = hex(int(sNewBinary, 2))[2:].zfill(16)
    return sDESKey

def sDEStoNTLMPart(sDESKey):
    ## Turn the 64 bit DES Key into a 64 bits binary string)
    sBinaryDESKey = bin(int(sDESKey, 16))[2:].zfill(64)
    ## Walk over the bits per 8 bits and remove the right most bit (should be a 1), it becomes 56bits
    sNewBinary = ''
    for i in range(0,64,8):
        sNewBinary += sBinaryDESKey[i:i+7]
        if not sBinaryDESKey[i+7:i+8] == '1': print('Warning: Is this a valid NTLMv1 DES Key?')
    ## Convert the new 56 bits back to a hex string
    sNTLMPart = hex(int(sNewBinary, 2))[2:].zfill(14)
    return sNTLMPart

### Converting an NTLM to two DES keys?
## NTLM == 16 bytes, but we only use 14 bytes (112bits)
## DES keys are 8 bytes (64bits), so we get 2 DES keys from one NTLM hash
#   we will devide the first 112bits in 2 halves of 56 bits each, the NTLM parts
#   These parts will be divided into 8 times 7 bits, NTLM segments, we add one '1' bit to each segment binary
#   So 8*7 becomes 8*8 bits == 64 bits == 8 bytes == our DES key
#  In theory, this added '1' bit is a parity bit mod(2) for the sum of all segments of the NTLM Part
if __name__ == '__main__':
    usage = '''usage: {} <NTLM> or {} <DES1> <DES2>\n
    It either converts an NTLM to the corresponding DES keys
    Or converts the DES keys to the original NTLM hash
        (only first 14 bytes, use hashcat-utils ct3_to_ntlm for the rest)
    '''.format(os.path.basename(sys.argv[0]), os.path.basename(sys.argv[0]))
    if len(sys.argv) == 1:
        print(usage)
        exit(0)
    elif len(sys.argv) == 2:
        sNTLM = sys.argv[1].strip()
        if not len(sNTLM) == 32:
            print('Error: Incorrect NTLM hash: Need 32 chars, got {}'.format(len(sNTLM)))
            exit(0)
        print('DESkey1: {}'.format(sNTLMPartToDES(sNTLM[:14])))
        print('DESkey2: {}'.format(sNTLMPartToDES(sNTLM[14:28])))
    elif len(sys.argv) == 3:
        sDES1 = sys.argv[1].strip()
        sDES2 = sys.argv[2].strip()
        if not len(sDES1) == 16:
            print('Error: Incorrect first DES key: Need 16 chars, got {}'.format(len(sDES1)))
            exit(0)
        elif not len(sDES2) == 16:
            print('Error: Incorrect second DES key: Need 16 chars, got {}'.format(len(sDES2)))
            exit(0)
        print('First 14 bytes of NTLM: {}'.format(sDEStoNTLMPart(sDES1) + sDEStoNTLMPart(sDES2)))
