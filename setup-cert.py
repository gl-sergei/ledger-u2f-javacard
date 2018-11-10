#! /usr/bin/env python
"""
Sample script that defines a custom card connection observer.

__author__ = "http://www.gemalto.com"

Copyright 2001-2012 gemalto
Author: Jean-Daniel Aussel, mailto:jean-daniel.aussel@gemalto.com

This file is part of pyscard.

pyscard is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

pyscard is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with pyscard; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
from __future__ import print_function
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString, toBytes
import struct
import argparse


class TracerAndSELECTInterpreter(CardConnectionObserver):
    """This observer will interprer SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, ccevent):

        if 'connect' == ccevent.type:
            print('connecting to ' + cardconnection.getReader())

        elif 'disconnect' == ccevent.type:
            print('disconnecting from ' + cardconnection.getReader())

        elif 'command' == ccevent.type:
            str = toHexString(ccevent.args[0])
            str = str.replace("A0 A4 00 00 02", "SELECT")
            str = str.replace("A0 C0 00 00", "GET RESPONSE")
            print('>', str)

        elif 'response' == ccevent.type:
            if [] == ccevent.args[0]:
                print('<  []', "%-2X %-2X" % tuple(ccevent.args[-2:]))
            else:
                print('<',
                      toHexString(ccevent.args[0]),
                      "%-2X %-2X" % tuple(ccevent.args[-2:]))

def send_apdu(s):
    apdu = toBytes(s)
    response, sw1, sw2 = cardservice.connection.transmit(apdu)
    if sw1 != 0x90:
        print('FAIL')

parser = argparse.ArgumentParser()
parser.add_argument("--attestation-cert", help="EC private cert in DER format")
args = parser.parse_args()

if not args.attestation_cert:
    raise Exception("--attestation-cert is required")


# we request any type and wait for 10s for card insertion
cardtype = AnyCardType()
cardrequest = CardRequest(timeout=10, cardType=cardtype)
cardservice = cardrequest.waitforcard()

# create an instance of our observer and attach to the connection
observer = TracerAndSELECTInterpreter()
cardservice.connection.addObserver(observer)

# connect and send APDUs
# the observer will trace on the console
cardservice.connection.connect()
send_apdu("00 A4 04 00 08 A0 00 00 06 47 2F 00 01")

offset = 0
chunk_size = 200
with open(args.attestation_cert, 'rb') as f:
    bts = f.read()
    while len(bts) > 0:
        chunk = bts[:chunk_size]
        print("F001" + format(offset, '04X') + format(len(chunk), '02X') + chunk.hex())
        print("\n")
        send_apdu("F001" + format(offset, '04X') + format(len(chunk), '02X') + chunk.hex())
        bts = bts[chunk_size:]
        offset = offset + chunk_size

import sys
if 'win32' == sys.platform:
    print('press Enter to continue')
    sys.stdin.read(1)
