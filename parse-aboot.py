#!/usr/bin/env python

import struct
import sys
import os
import hashlib
import binascii

from pyasn1_modules import  rfc2437,rfc2459
from pyasn1.codec.der import decoder

import rsa
from rsa import common, transform, core

ABOOT_HEADER_LEN = 40
ABOOT_MAGIC = b'\x00\x00\x00\x05'

SHA1_HASH_SIZE = 20
SHA256_HASH_SIZE = 32

class AbootHeader:
    def parse(self, aboot):
        (magic, version, null, img_base, img_size, code_size, img_base_code_size, sig_size, code_sig_offset, cert_size) = struct.unpack('< 10I', aboot[0:ABOOT_HEADER_LEN])
        self.magic = magic
        self.version = version
        self.null = null
        self.img_base = img_base
        self.img_size = img_size
        self.code_size = code_size  
        self.img_base_code_size = img_base_code_size
        self.sig_size = sig_size
        self.code_sig_offset = code_sig_offset
        self.cert_size = cert_size

    def dump(self):
        print('aboot header:')
        print('-' * 40)
        print('magic:             0x%08x' % self.magic)
        print('version:           0x%08x' % self.version)
        print('NULL:              0x%08x' % self.null)
        print('ImgBase:           0x%08x' % self.img_base)
        print('ImgSize:           0x%08x (%d)' % (self.img_size, self.img_size))
        print('CodeSize:          0x%08x (%d)' % (self.code_size, self.code_size))
        print('ImgBaseCodeSize:   0x%08x' % self.img_base_code_size) 
        print('SigSize:           0x%08x (%d)' % (self.sig_size, self.sig_size))
        print('CodeSigOffset:     0x%08x' % self.code_sig_offset)
        print('Certs size:        0x%08x (%d)' % (self.cert_size, self.cert_size))
        print()

    def sig_offset(self):
        return ABOOT_HEADER_LEN + self.code_size

    def cert_offset(self):
        return self.sig_offset()  + self.sig_size

def dump_signature(aboot, header, filename):
    sig_offset = header.sig_offset()
    print('SigOffset:         0x%08x' % sig_offset)
    print() 

    fmt = '< %ds' % header.sig_size
    sig = struct.unpack(fmt, aboot[sig_offset:sig_offset + header.sig_size])[0]
    with open(filename, 'wb') as f:
        f.write(sig)

    return sig

def frombits(bits):
    zero_one_string = str(bits)
    return int(zero_one_string, 2).to_bytes((len(zero_one_string) + 7) // 8, 'big')

# only the bits we need. 
# Cf. https://www.qualcomm.com/documents/secure-boot-and-image-authentication-technical-overview
#OU=07 0001 SHA256
#OU=06 00XX MODEL_ID
#OU=05 0000XXXX SW_SIZE
#OU=04 00XX OEM_ID
#OU=03 0000000000000002 DEBUG
#OU=02 00XXXXXXXXXXXXXX HW_ID
#OU=01 000000000000000X SW_ID
class CertInfo:
    control_fields = []     
    pub_key = None
    cert_len = 0

    def get_control_field(self, cf_name):
        if not self.control_fields:
            return None

        for cf in self.control_fields:
            if cf_name in cf:
                return binascii.unhexlify(cf.split(' ')[1])

        return None

    def get_sw_id(self):
        return self.get_control_field('SW_ID')

    def get_hw_id(self):
        return self.get_control_field('HW_ID')

    def is_sha256(self):
        return b'\x00\x01' == self.get_control_field('SHA256')

def parse_cert(raw_bytes):
    result = CertInfo()
    certType = rfc2459.Certificate();	
    cert, rest = decoder.decode(raw_bytes, asn1Spec=certType)
    subj_pub_key_bytes = frombits(cert.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey'))
    SUBJECT = cert.getComponentByName('tbsCertificate').getComponentByName('subject')
    for rdn in SUBJECT[0]:
        for nv in rdn: 
            name = nv.getComponentByName('type')
            value = nv.getComponentByName('value')
            # could pick up regular OUs too
            if name == rfc2459.id_at_organizationalUnitName:
                result.control_fields.append(str(value).strip())

    rsaType = rfc2437.RSAPublicKey();
    rsadata,rsadata_rest = decoder.decode(subj_pub_key_bytes, asn1Spec=rsaType)
    mod = rsadata.getComponentByName("modulus")
    pub_exp = rsadata.getComponentByName("publicExponent")
    result.pub_key = rsa.PublicKey(int(mod), int(pub_exp))

    return result

def dump_cert(aboot, cert_offset, filename):
    # DIY ASN.1
    #print(aboot[cert_offset:cert_offset+10].hex())
    if aboot[cert_offset] == 0x30 and aboot[cert_offset + 1] == 0x82:
        seq_len = struct.unpack('> H', aboot[cert_offset + 2:cert_offset + 4])[0]
        cert_len = seq_len + 4

        fmt = '< %ds' % cert_len
        cert = struct.unpack(fmt, aboot[cert_offset:cert_offset + cert_len])[0]
        with open(filename, 'wb') as f:
            f.write(cert)
        cert_info = parse_cert(cert)
        cert_info.cert_len = cert_len

        return cert_info
    else:
        return None

def xor(key, pad):
    result = bytearray(len(key))
    result[:] = key[:]

    p = bytearray(len(pad))
    p[:] = pad[:]

    for i in range(len(p)):
        result[i] ^= p[i]

    return (result)

def digest(data, is_sha256):
    md = hashlib.sha256() if is_sha256 else hashlib.sha1()
    md.update(data)
    return md.digest()

def calc_hash(aboot_base, hw_id, sw_id, is_sha256):
    o_pad = b'\x5c' * 8
    i_pad = b'\x36' * 8

    h0 = digest(aboot_base, is_sha256)
    sw_id_ipad = xor(sw_id, i_pad)
    hw_id_opad = xor(hw_id, o_pad)

    m1 = bytearray(len(sw_id_ipad) + len(h0))
    m1[0:len(sw_id_ipad)] = sw_id_ipad[:]
    m1[len(sw_id_ipad):] = h0[:]
    h1 = digest(m1, is_sha256)

    m2 = bytearray(len(hw_id_opad) + len(h1))
    m2[0:len(hw_id_opad)] = hw_id_opad[:]
    m2[len(hw_id_opad):] = h1[:]
    h2 = digest(m2, is_sha256)
    return h2

def extract_raw_hash(signature, pub_key, is_sha256):
    hash_size = SHA256_HASH_SIZE if is_sha256 else SHA1_HASH_SIZE
    keylength = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = transform.int2bytes(decrypted, keylength)
    # unpad
    if (clearsig[0] != 0x00 or clearsig[1] != 0x01):
        raise Exception('Invalid signature format')

    null_idx = clearsig.find(b'\x00', 2)
    if null_idx < 0:
        raise Exception('Invalid signature format')

    padding = clearsig[2:null_idx]
    if len(padding) != keylength - 2 - 1 - hash_size:
        raise Exception('Invalid signature format 1')
    if not all(p == 0xff for p in padding):
        raise Exception('Invalid signature format 2')

    raw_hash = clearsig[null_idx + 1:]
    if len(raw_hash) != hash_size:
        raise Exception('Invalid signature format 3.')

    return raw_hash

def dump_all_certs(aboot, header, base_filename):
    cert_infos = []
    cert_offset = header.cert_offset()

    cert_num = 1
    cert_size = 0
    if cert_offset <= 0:
        print('No certificates found')
        return cert_infos

    print('Dumping all certificates...')
    while cert_offset < len(aboot):
        filename = '%s-%d.cer' % (base_filename, cert_num)
        cert_info = dump_cert(aboot, cert_offset, filename)
        if (cert_info is None):
            break

        print('cert %d: %s, size: %4d' % (cert_num, filename, cert_info.cert_len))
        cert_infos.append(cert_info)

        cert_num += 1
        cert_offset = cert_offset + cert_info.cert_len
        cert_size += cert_info.cert_len

    print('Total cert size         : %4d' % cert_size)
    print()

    return cert_infos
	
try:
    __file__
except:
    sys.argv = [sys.argv[0], 'aboot.bin']
	
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: %s aboot.img' % sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
       aboot = bytes(f.read())
    print('aboot image %s, len=%d' % (sys.argv[1], len(aboot)))
    
    header = AbootHeader()
    header.parse(aboot)
    header.dump()

    if header.magic != 0x5:
        print('Unrecognized format, magic=0x%04x' % header.magic)
        sys.exit(1)

    sig = dump_signature(aboot, header, 'signature.bin')

    if (header.cert_size == 0):
        print('No embedded certifictes found or unknown format')
        sys.exit(1)

    cert_infos = dump_all_certs(aboot, header, 'cert')

    # assume [0] is leaf/signing cert
    expected_hash = extract_raw_hash(sig, cert_infos[0].pub_key, cert_infos[0].is_sha256())
            
    print('Trying to calculate image hash...')
    hw_id = cert_infos[0].get_hw_id()
    sw_id = cert_infos[0].get_sw_id()
    if hw_id is None or sw_id is None:
        raise Exception('Could not find HW_ID or SW_ID')

    # both header and code are signed
    aboot_sig_target = aboot[0:ABOOT_HEADER_LEN + header.code_size]
    my_hash = calc_hash(aboot_sig_target, hw_id, sw_id, cert_infos[0].is_sha256())

    print('Expected: %s (%d)' % (expected_hash.hex(), len(expected_hash)))
    print('My hash:  %s (%d)' % (my_hash.hex(), len(my_hash)))
    if my_hash == expected_hash:
        print('Hashes match')
    else:
        print('Hashes don\'t match')


