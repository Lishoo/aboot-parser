# Android aboot and ELF image parser

Script to parse Android images (aboot and ELF), extract certificates and verify image signature.

May not work on aboot from latest devices. Signature verification follows the 
'Secure Boot and Image Authentication Technical Overview' whitepaper by Qualcomm.
Cf. https://www.qualcomm.com/documents/secure-boot-and-image-authentication-technical-overview-v10

aboot header format as described in http://newandroidbook.com/Articles/aboot.html
See above article for more details about aboot. 

Based on work from https://github.com/nelenkov/aboot-parser

Tested on aboot from
 * Nexus 5
 * Kyocera Brigadier 
 * Kyocera KC-S701
 * LG L70
 
 Tested on all ELF images from
 * LG G6
 * LG Stylo 4
 
Nexus 5X/6P use the ELF format, as described in QC whitepaper. 
Currently not tested by this version of script.

Usage:

```
$ ./parse-aboot.py elf.img 
aboot image elf.img, len=694784

ELF file format found!

aboot header:
----------------------------------------
magic:             0x00000000
version:           0x00000003
NULL:              0x00000000
ImgBase:           0x8f68e028
ImgSize:           0x00001980 (6528)
CodeSize:          0x00000080 (128)
ImgBaseCodeSize:   0x8f68e0a8
SigSize:           0x00000100 (256)
CodeSigOffset:     0x8f68e1a8
Certs size:        0x00001800 (6144)

SigOffset:         0x000000a8

Dumping all certificates...
cert 1: cert-1.cer, size: 1168
cert 2: cert-2.cer, size: 1129
cert 3: cert-3.cer, size:  941
Total cert size         : 3238

Trying to calculate image hash...
Expected: 826c971a5561de2ecc83459f222782a4044933d674e9d401d69176321e128d08 (32)
My hash:  826c971a5561de2ecc83459f222782a4044933d674e9d401d69176321e128d08 (32)
Hashes match
```


