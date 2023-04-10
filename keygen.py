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

import argparse
import sys
import base64
from datetime import datetime

import dns.name
import dns.tokenizer
import dns.dnssec

def write_keyfile ( fn, content ):
  '''
    @param fn  prefix of .key/.private file name.
    @param content  dict, sutff for gen keyfile,
                    including timestamp,domain,flags,
                    protocol,algorithm,keytag,pubkey,prikey
  '''

  dt = content['dt']
  flags = content['flags']

  dt1 = dt.strftime('%a %b %d %H:%M:%S %Y')
  dt2 = dt.strftime('%Y%m%d%H%M%S')

  if flags == 256:
    flag = 'zone-signing'
  elif flags == 257:
    flag = 'key-signing'

  # write .key file
  keyfile = fn+'.key'
  print(' public key file:   %s' % keyfile)
  f = open( keyfile, "w" )
  f.write( """; This is a %s key, keyid %d, for %s
; Created: %s (%s)
; Publish: %s (%s)
; Activate: %s (%s)
%s IN DNSKEY %d %d %d %s
"""
    % 
    ( 
     flag, keytag, content['domain'], 
     dt1, dt2, 
     dt1, dt2, 
     dt1, dt2, 
     content['domain'], flags, content['protocol'], content['algorithm'], content['pubkey']
    )
  )
  f.close()

  # write .private file
  keyfile = fn+'.private'
  print('private key file:   %s' % keyfile)
  f = open( keyfile, "w" )
  f.write( """Private-key-format: v1.3
Algorithm: 17 (SM2SM3)
PrivateKey: %s
Created: %s
Publish: %s
Activate: %s
"""
    %
    (
     content['prikey'],
     dt1,
     dt1,
     dt1
    )
  )
  f.close()

if __name__ == "__main__":
  print("testcase 0:generated 2:27215 key")
  testcase = 0
  print("testcase: %s" % testcase)

  if testcase == 2:
    # fixed keytag 27215
    domain='example.net.'
    flags=257
    protocol=3
    algorithm=17
    pubkey='jZbZMBImG9dtGWSVEwnv2l32OVKcX7MMJv+83/+A41iaZuO0ajXMcuyJbTr8Ud+kae6UlfqrnsG6tgADIPHxXA=='
    prikey='V24tjJgXxp2ykscKRZdT+iuR5J1xRQN+FKoQACmo9fA='
  else:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zonename", "-o", help="zonename", required=True)
    parser.add_argument("--keytype", "-k", help="ksk or zsk")
    args = parser.parse_args()
    # print(args)

    zonename = args.zonename
    flag = args.keytype
    protocol = 3
    algorithm = 17

    if zonename[-1]=='.':
      domain = zonename
    else:
      domain = zonename + '.'

    if flag == 'ksk':
      flags = 257
    elif flag == 'zsk':
      flags = 256
    else:
      print('wrong key type.')

    priKey = PrivateKey()
    pubKey = priKey.publicKey()
    print("== Newly generated sm2 keys:")
    print('private key ( generating RRSIG RR ):  %s' % priKey.toString())
    print('public key ( validating RRSIG RR ): \n%s' % pubKey.toString(False))

    pubkey = base64.b64encode(bytes.fromhex(pubKey.toString(False)))
    pubkey = pubkey.decode()
    prikey = base64.b64encode(bytes.fromhex(priKey.toString()))
    prikey = prikey.decode()

  name = dns.name.from_text(domain)
  DNSKEYRR = ' '.join ( [name.to_text(),
    "IN DNSKEY", str(flags), str(protocol), str(algorithm), 
    pubkey])
  tok = dns.tokenizer.Tokenizer(DNSKEYRR)
  name = tok.get_name()
  rdclass = tok.get_string()
  rdtype = tok.get_string()
  tmpRR = dns.rdata.from_text(rdclass, rdtype, tok, name)
  keytag = dns.dnssec.key_id(tmpRR)

  keyfile = 'keys/' + 'K%s+%s+%d'%(domain, str(algorithm).zfill(3), keytag)
  dt = datetime.now()
  content = {
   'dt' : dt,
   'domain' : domain,
   'flags' : flags,
   'protocol' : protocol,
   'algorithm' : algorithm,
   'keytag' : keytag,
   'pubkey' : pubkey,
   'prikey' : prikey
  }
  print("\n== generating key files.")
  write_keyfile( keyfile, content )

  if flags == 257:
    print("\n\n== -k", keyfile)
  elif flags == 256:
    print("\n\n== -z", keyfile)

  print("\n== Don't forget to copy DNSKEY RR into zonefile.")
