# NTLMv1 Multi Tool
This tool reverses NTLMv1 hashes to NTLM, or more specifically it formats NTLMv1 challenge responses into a format that can be cracked with hashcat mode 14000

# 10 Nov, 2020 Updates
I added 2 new options, `--hashcat` and `--hcutils` these set the path to your hashcat and hashcat-utils respectively so you can do a direct copy and paste from the tool.

You would run the tool like this if your hashcat directory was in ~/git/hashcat and your hashcat-utils directory was in ~/git/hashcat-utils:
```
python3 ./ntlmv1.py --ntlm "SERVER1$::MOG:9DE7F41D81C1207400000000000000000000000000000000:DE766A98B60D1C911DCFFFDBB3E521314B2CE34EAB63CC7B:1122334455667788" --hashcat "~/git/hashcat" --hcutils "~/git/hashcat-utils"
```

# Dec 10, 2019 Updates
Yes this is supposedly python 3 compatible, I have also merged ntlmv1 and ntlmv1-ess

# ntlmv1-multi
NTLMv1 Multitool

This tool modifies NTLMv1/NTLMv1-ESS/MSCHAPv2 hashes so they can be cracked with DES Mode 14000 in hashcat

This tool is based on work done by atom of team Hashcat https://hashcat.net/forum/thread-5832.html

It is also based on https://hashcat.net/forum/thread-5912.html and https://www.youtube.com/watch?v=LIHACAct2vo

# Usage

## NTLMv1 without ESS
To capture use responder with the --lm flag, without --lm you will activate ESS which will take longer to crack, also a new flag is out --disable-ess which will try to disable ESS and force the downgrade. Try --disable-ess first and if that fails please try --lm. If using --disable-ess or --lm ensure your client challenge is 1122334455667788 to use the FPGA, however this may trigger some network IDS/IPS protections if they see that traffic.

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

So use the multi tool like so (its also python 2 compatible)
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
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

The password used in this case is "password" and we can verify the ntlm hash with
```
echo -n password | iconv -f utf8 -t utf16le | openssl dgst -md4
(stdin)= 8846f7eaee8fb117ad06bdd830b7586c
```

With hashcat utils ct3_to_ntlm.bin that atom wrote you can calculate the last 4 characters of the NTLM hash from the NTLMv1 challenge, which the tool outputs
```
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788
586c
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

An important note is that hashcat will return DES keys and not NTLM keys, you will need to convert to NTLM using `deskey_to_ntlm.pl` from [Hashcat Utils](https://github.com/hashcat/hashcat-utils/releases/), this can be accomplished with
```
./deskey_to_ntlm.pl [cracked des key 1]
./deskey_to_ntlm.pl [cracked des key 2]
```

you then combine the two ntlm keys with the third part of the password. Calculated by (whatever the tool outputs)
```
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788
```

Add those 3x together and you are good to go

### Testing with the des converter

If you are just testing my code and know the password already you can use the des converter
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo "$HEX[b55d6d04e67926]">>des.cand
echo "$HEX[bcba83e6895b9d]">>des.cand
```

Basically you do the following
```
echo "$HEX[b55d6d04e67926]">>des.cand
echo "$HEX[bcba83e6895b9d]">>des.cand
```

```
./hashcat -m 14000 -a 0 hashes.txt des.cand
```

And you should have some reversed hashes

## NTLMv1 with ESS
ESS changes the server challenge, if you see ESS in your responder because you didn't use --lm or the client is set not to give out a LM response then ESS gets engaged. Also --disable-ess will try to force off ESS, however this requires a recent copy (August 2021 or more recent) of impacket and responder.

The ESS output looks like this
```
[SMB] NTLMv1-SSP Client   : 184.64.60.62
[SMB] NTLMv1-SSP Username : DUSTIN-5AA37877\hashcat
[SMB] NTLMv1-SSP Hash     : hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788
```

The actual hash looks like this
```
hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788
```

To use the tool run (it is python3 compatible)
```
python3 ntlmv1.py --ntlmv1 "hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788"
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

So to calculate the last 4 characters of the ntlm hash for our NTLMv1-ESS chalenge we use the following command from the tool output to get ```586c```
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


An important note is that hashcat will return DES keys and not NTLM keys, you will need to convert to NTLM using `deskey_to_ntlm.pl` from [Hashcat Utils](https://github.com/hashcat/hashcat-utils/releases/), this can be accomplished with
```
./deskey_to_ntlm.pl [cracked des key 1]
./deskey_to_ntlm.pl [cracked des key 2]
```

Now assuming we already knew what the ntlm hash was in the case because we made it and want to validate the tooling we use the following
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
```

This will output some data for us
```
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo "$HEX[b55d6d04e67926]">>des.cand
echo "$HEX[bcba83e6895b9d]">>des.cand
```

The important part here is
```
echo "$HEX[b55d6d04e67926]">>des.cand
echo "$HEX[bcba83e6895b9d]">>des.cand
```

Now we can crack with hashcat using the following and not waiting 8 days
```
./hashcat -m 14000 -a 0 hashes.txt des.cand
```

## NTLM hash to DES Key Converter for data validation testing
```
python ntlm-to-des.py  --ntlm 8846f7eaee8fb117ad06bdd830b7586c
```
```
DESKEY1: b55d6d05e6792652
DESKEY2: bdba82e6895a9d6a

echo "$HEX[b55d6d05e6792652]">>des.cand
echo "$HEX[bdba82e6895a9d6a]">>des.cand
```

## JSON Support
The tool now supports json output, set the flag `--json 1` and it will output json output:

```
python3 ntlmv1.py --ntlmv1 "SERVER1$::MOG:7EF3F506F5EA510E00000000000000000000000000000000:1217169BD7BE0270A033899BD440016D3E6DACAF5894D504:ff81dfd6b12c269d" --json 1
{"ntlmv1": "SERVER1$::MOG:7EF3F506F5EA510E00000000000000000000000000000000:1217169BD7BE0270A033899BD440016D3E6DACAF5894D504:ff81dfd6b12c269d", "user": "SERVER1$", "domain": "MOG", "challenge": "ff81dfd6b12c269d", "lmresp": "7EF3F506F5EA510E00000000000000000000000000000000", "ntresp": "1217169BD7BE0270A033899BD440016D3E6DACAF5894D504", "ct3": "3E6DACAF5894D504", "srvchallenge": "888f8ee0fa031808", "ct3_crack": "ct3_to_ntlm.bin 3E6DACAF5894D504 ff81dfd6b12c269d 7EF3F506F5EA510E00000000000000000000000000000000", "hash1": "1217169BD7BE0270:888f8ee0fa031808", "hash2": "A033899BD440016D:888f8ee0fa031808", "CRACK_SH": "$NETLM$888f8ee0fa031808$1217169BD7BE0270A033899BD440016D3E6DACAF5894D504"}
```

The important fields are:
* hash1 - this is the first hash for hashcat mode 14000
* hash2 - this is the second hash for hashcat mode 14000
* ct3_crack - this is the command to crack ct3 using hashcat utils
* ntlmv1 - hthis is the original ntlmv1 hash
* user - this is the user field
* domain - this is the domain field
* lmresp - this is the lm response
* ntresp - this is the nt response
* challenge - this is the original challenge field
* srvchallenge - if this is an ESS hash the srv challenge gets populated

# Acknowledgement / License
This repo is based on forum posts by atom the author of hashcat and research by moxie marlinspike. as atoms code is largely MIT licensed this project has also adopted that license to be compatible. This project is not GPL so that any entity can incorporate it into a commercial project without restrictions.
