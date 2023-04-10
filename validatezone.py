# Copyright (c) 2023 Cathy Zhang scooct@163.com 

# Permission is hereby granted, free of charge, to any person obtaining 
# a copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included 
# in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
# IN THE SOFTWARE.

#!/usr/bin/env python3

import dns
import dns.zone
import dns.node
import dns.rdatatype

import base64
import binascii
from gmssl import sm2, func

import sys
import argparse

# argv[0]: script
# argv[1]: zonename
# argv[2]: filename

if len(sys.argv) < 3:
  print("parameter not correct")
  exit()

parser = argparse.ArgumentParser()
parser.add_argument("--zonename", "-o", help="zonename", required=True)
parser.add_argument("--zonefile", "-f", help="zonefile", required=True)
args = parser.parse_args()
#print(args)

ORIGIN=args.zonename
filename=args.zonefile
#ORIGIN='example'
zone = dns.zone.from_file(filename, origin=ORIGIN)

counter=1
rrsigcounter=1
nodes=zone.nodes

lastRRdataset=None
currentRRdataset=None

prefix="           ---- validation result is:"
for key in nodes:
  rdatasets=zone.nodes[key]
  for RRdataset in rdatasets:
    lastRRdataset=currentRRdataset
    currentRRdataset=RRdataset
    for Rdata in RRdataset:
      counter=counter+1
      if Rdata.covers() != dns.rdatatype.TYPE0:
        ownername=dns.name.from_text(key.to_text(), origin=zone.origin)
        rrsigcounter = rrsigcounter + 1
        try:
            (data, sig, pubkey) = dns.dnssec.extract_validation_info( (key, lastRRdataset), Rdata, zone.nodes, zone.origin )
            sm2_crypt = sm2.CryptSM2(private_key=None,
                        public_key=pubkey.key.hex())
            validation_result=sm2_crypt.verify_with_sm3(str(sig.hex()), data)
            keytag = dns.dnssec.key_id(pubkey)
            if validation_result:
              print( "[ %s ] RRset of [ %s ] could be verified with DNSKEY(keyid [ %d] )." % (dns.rdatatype.to_text(lastRRdataset.rdtype), ownername, keytag) )
            else:
              print( "[ %s ] RRset of [ %s ] could NOT be verified with DNSKEY(keyid [ %d] )." % (dns.rdatatype.to_text(lastRRdataset.rdtype), ownername, keytag) )
        except:
            print( "[ %s ] RRset of [ %s ] has no matched RRSIG with existed DNSKEY." % (dns.rdatatype.to_text(lastRRdataset.rdtype), ownername) )
