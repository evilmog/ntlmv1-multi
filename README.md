# ntlmv1-multi
NTLMv1 Multitool

This tool modifies NTLMv1/NTLMv1-ESS/MSCHAPv1 hashes so they can be cracked with DES Mode 14000 in hashcat

This tool is based on work done by atom of team Hashcat https://hashcat.net/forum/thread-5832.html

It is also based on https://hashcat.net/forum/thread-5912.html and https://www.youtube.com/watch?v=LIHACAct2vo

# Usage

## NTLMv1-ESS
```
python ntlmv1-ess.py --ess "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c"
```

```
['hashcat', '', 'DUSTIN-5AA37877', '85D5BC2CE95161CD00000000000000000000000000000000', '892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
LM Response: 85D5BC2CE95161CD00000000000000000000000000000000
NT Response: 892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0
Client Challenge: 85D5BC2CE95161CD
SRV Challenge: b36d2b9a8607ea77

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin 2BBD6C9ABCD021D0 85D5BC2CE95161CD 85D5BC2CE95161CD00000000000000000000000000000000

To crack with hashcat create a file with the following contents:
892F905962F76D32:b36d2b9a8607ea77
3837F613F88DE27C:b36d2b9a8607ea77

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

## NTLMv1 no ESS
```
python ntlmv1.py --noess 'hashcat::DUSTIN-5AA37877:E343946E455EFC72746CF587C42022982F85252CC731BB25:51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C:1122334455667788'
```

```
Hashfield Split:
['hashcat', '', 'DUSTIN-5AA37877', 'E343946E455EFC72746CF587C42022982F85252CC731BB25', '51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C', '1122334455667788']

Hostname: DUSTIN-51137877
Username: hashcat
Challenge: 1122334455667788
Combined: 51A539E6EE061F647CD5D48CE6C686653737C5E1DE26AC4C
CT1: 51A539E6EE061F64
CT2: 7CD5D48CE6C68665
CT3: 3737C5E1DE26AC4C

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin 3737C5E1DE26AC4C 1122334455667788

To crack with hashcat create a file with the following contents:
51A539E6EE061F64:1122334455667788
7CD5D48CE6C68665:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```


## NTLMv1 JTR
```
python ntlmv1-jtr.py --jtr '$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233'
```

```
['', 'NETNTLM', '1122334455667788', 'B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233']

Challenge: 1122334455667788
Combined: B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233
CT1: B2B2220790F40C88
CT2: BCFF347C652F67A7
CT3: C4A70D3BEBD70233

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin C4A70D3BEBD70233 1122334455667788

To crack with hashcat create a file with the following contents:
B2B2220790F40C88:1122334455667788
BCFF347C652F67A7:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

## NTLM hash to DES Key Converter for data validation testing
```
python ntlm-to-des.py  --ntlm 8846f7eaee8fb117ad06bdd830b7586c
```
```
DESKEY1: 8922bdfdae753e62
DESKEY2: 16d641d6ddc1c26e
```
