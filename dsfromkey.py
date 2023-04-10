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

from gmssl import sm2, func, sm3
from gmssl.utils import PrivateKey

import dns
import dns.name
import dns.dnssec

import sys
import base64
from datetime import datetime

if __name__ == "__main__":

# argv[0]: script
# argv[1]: .key filename

  if len(sys.argv) < 2:
    print("parameter not correct")
    exit()

  keyfile = sys.argv[1]

  f = open( keyfile, "r" )
  for line in f.readlines():
    line = line.strip()
    if line.startswith(";") or line == "":
      continue
    else:
      (zonename, cls, type, flags, protocol, algorithm, pubkey) = line.split(" ")

  if zonename[-1]=='.':
    domain = zonename
  else:
    domain = zonename + '.'

  name = dns.name.from_text(domain)
  DNSKEYRR = ' '.join ([ "IN DNSKEY", 
    str(flags), str(protocol), str(algorithm), pubkey ])
  tok = dns.tokenizer.Tokenizer(DNSKEYRR)
  rdclass = tok.get_string()
  rdtype = tok.get_string()
  tmpRR = dns.rdata.from_text(rdclass, rdtype, tok, name)
  keytag = dns.dnssec.key_id(tmpRR)

  DSRdata = dns.dnssec.make_ds(name, tmpRR, dns.dnssec.DSDigest.SM3)
  print(name, rdclass, 'DS', DSRdata)
