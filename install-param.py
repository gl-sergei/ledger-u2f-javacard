#!/usr/bin/env python

#
# Use this script to inject your own private key and authentication counter
# into U2F binary. Might be useful if you want keys to survive firmware updates.
#
# Example:
#
# Generate EC private key with openssl:
# > openssl ecparam -name prime256v1 -genkey -noout -outform der > key.der
#
# Inject generated key into u2f.bin and set auth counter to 100:
# > python3 inject_key.py --key key.der --ctr 100
#

from __future__ import print_function
from asn1crypto.keys import ECPrivateKey
import hashlib
import argparse
import sys
import struct
import os
import tempfile
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--key", help="EC private key in DER format")
parser.add_argument("--attestation-key", help="EC private key in DER format for attestation certificate")
parser.add_argument("--attestation-cert", help="for attestation certificate in DER format")
parser.add_argument("--wrapping-key", help="ASE128 wrapping key in DER format")
args = parser.parse_args()

if args.attestation_key:
    with open(args.attestation_key, "rb") as f:
        der = f.read()
else:
    raise Exception("--attestation-key is required")
attestation_key = ECPrivateKey.load(der)

if args.key:
    with open(args.key, "rb") as f:
        der = f.read()
    key = ECPrivateKey.load(der)
else:
    key = None

if args.wrapping_key:
    with open(args.wrapping_key, "rb") as f:
        wrapping_key_bytes = f.read()
    if len(wrapping_key_bytes) != 16:
        raise Exception("--wrapping-key length has to be 16 bytes")
else:
    wrapping_key_bytes = None

if args.wrapping_key and not args.key:
    raise Exception("--wrapping-key is set but --key is missing")

if not args.wrapping_key and args.key:
    raise Exception("--key is set but --wrapping-key is missing")

if args.attestation_cert:
    stat = os.stat(args.attestation_cert)
    attestation_cert_len = stat.st_size
else:
    raise Exception("--attestation-cert is required")

# convert key into raw bytes and calculate it's sha256
param_hex = format(attestation_key["private_key"].native, '064x')
if key:
    param_hex = param_hex + format(key["private_key"].native, '064x')
    param_hex = param_hex + wrapping_key_bytes.hex()

param_hex = '00' + format(attestation_cert_len, '04x') + param_hex

print(param_hex)
