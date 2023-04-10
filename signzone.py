# Copyright (c) 202 Cathy Zhang scooct@163.com 

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
import dns.dnssec
import dns.zone
import dns.node
import dns.rdatatype

import sys
import time, datetime
import argparse
import struct
import base64
import binascii
import json
from gmssl import sm2, func

def generate_signature ( ownername, RRdataset, Rdata, data, prikey, pubkey ):
  '''
    with given target RR set, generate signature with SM2SM3 algorithm. 

    @param ownername  ownername of RRSIG RR
    @param RRdataset  RRdataset to be signed
    @param Rdata  Rdata of RRSIG RR
    @param data  original data before signed
    @param prikey  SM2 prikey used to sign data
    @param pubkey  SM2 pubkey used to validate data(not used, but can't be omitted)

    @return  a RRSIG RR string.
  '''

  sm2_crypt = sm2.CryptSM2(private_key=prikey.hex(),
    public_key=pubkey.hex())
  signature=sm2_crypt.sign_with_sm3(data)
  signature_bytes = bytes.fromhex(signature)
  base64sigbytes = base64.b64encode(signature_bytes)
  base64sigstr = base64sigbytes.decode()

  RRstr = ('%s %d %s %s %s %d %d %d %s %s %d %s %s' % (
    dns.name.from_text(ownername.to_text(), origin=zone.origin),
    RRdataset.ttl,
    dns.rdataclass.to_text(RRdataset.rdclass),
    dns.rdatatype.to_text(Rdata['rdatatype']),
    dns.rdatatype.to_text(Rdata['type_covered']),
    Rdata['algorithm'],
    Rdata['labels'],
    Rdata['original_ttl'],
    time.strftime('%Y%m%d%H%M%S', time.gmtime(Rdata['expiration'])),
    time.strftime('%Y%m%d%H%M%S', time.gmtime(Rdata['inception'])),
    Rdata['key_tag'],
    Rdata['signer'],
    base64sigstr
    )
   )
  return RRstr

def generate_new_RRSIG ( zone, params ):
  '''
    Sign a zone with given ZSK/KSK.

    @param zone  zone data from zonefile
    @param params  parameters used to gen RRSIG RR
      ksk_prikey  private key of ksk
      ksk_pubkey  public key of ksk
      ksk_keytag  keytag of ksk
      zsk_prikey  private key of zsk
      zsk_pubkey  public key of zsk
      zsk_keytag  keytag of zsk
      expiration  timestamp of signature expiration
      inception  timestamp of signature inception
      default_ttl  default ttl of RRSIG RR
  }
  '''

  expiration = params['expiration']
  inception = params['inception']
  ksk_prikey = params['ksk_prikey']
  ksk_pubkey = params['ksk_pubkey']
  ksk_keytag = params['ksk_keytag']
  zsk_prikey = params['zsk_prikey']
  zsk_pubkey = params['zsk_pubkey']
  zsk_keytag = params['zsk_keytag']

  DNSKEY_flag = False
  signed_zone =[]
  nodes=zone.nodes

  zsk_DNSKEY_match = False
  ksk_DNSKEY_match = False

  # Step 1: Find common RR and gen corresponding RRSIG
  for ownername in nodes:
    rdatasets=zone.nodes[ownername]
    for RRdataset in rdatasets:
      if RRdataset.rdtype ==  dns.rdatatype.RRSIG or \
         RRdataset.rdtype ==  dns.rdatatype.NSEC3 or \
         RRdataset.rdtype ==  dns.rdatatype.NSEC3PARAM:
        continue
      else :
        for RRdata in RRdataset:
          RRstr = ' '.join([
            dns.name.from_text(ownername.to_text(), origin=zone.origin).to_text(),
            str(RRdataset.ttl),
            dns.rdataclass.to_text(RRdataset.rdclass),
            dns.rdatatype.to_text(RRdataset.rdtype),
            RRdata.to_text(origin=zone.origin, relativize=False)])
          signed_zone.append( RRstr )
      type_covered = int(RRdataset.rdtype)
      algorithm = int(dns.dnssec.Algorithm.SM2SM3)
      labels = ownername.derelativize(zone.origin).to_text().count(".")
      original_ttl = RRdataset.ttl
      signer = zone.origin

      key_tag = zsk_keytag
      prikey = zsk_prikey
      pubkey = zsk_pubkey

      header = struct.pack('!HBBIIIH', type_covered,
               algorithm, labels,
               original_ttl, expiration,
               inception, key_tag)
      header += signer.to_wire()
      data = header + dns.dnssec.extract_unsigned_data( (ownername, RRdataset), key_tag, original_ttl, origin=zone.origin)
      Rdata = { 'type_covered': type_covered, 
        'rdatatype' :46,
        'algorithm' : int(dns.dnssec.Algorithm.SM2SM3),
        'labels' : labels,
        'original_ttl' : original_ttl,
        'expiration' : expiration,
        'inception' : inception,
        'key_tag' : key_tag,
        'signer' : signer
      }

      RRstr = generate_signature( ownername, RRdataset, Rdata, data, prikey, pubkey )
      signed_zone.append( RRstr )
      if dns.rdatatype.to_text(Rdata['type_covered']) == 'DNSKEY':
        DNSKEY_flag = True
        key_tag = ksk_keytag
        header = struct.pack('!HBBIIIH', type_covered,
                 algorithm, labels,
                 original_ttl, expiration,
                 inception, key_tag)
        header += signer.to_wire()
        data = header + dns.dnssec.extract_unsigned_data( (ownername, RRdataset), key_tag, original_ttl, origin=zone.origin)
        Rdata['key_tag'] = key_tag
        RRstr = generate_signature( ownername, RRdataset, Rdata, data, ksk_prikey, ksk_pubkey )
        signed_zone.append( RRstr )
        
        for RR in RRdataset:
          tmp_keytag = dns.dnssec.key_id(RR)
          if tmp_keytag == zsk_keytag:
            zsk_DNSKEY_match = True
          if tmp_keytag == ksk_keytag:
            ksk_DNSKEY_match = True
  if not DNSKEY_flag:
    print("WARNING: Found NO DNSKEY RR in zonefile!!!")
  if not zsk_DNSKEY_match:
    print("WARNING: NO matched DNSKEY RR of zone signing private key found in zonefile!!!")
  if not ksk_DNSKEY_match:
    print("WARNING: NO matched DNSKEY RR of key signing private key found in zonefile!!!")

  key_tag = zsk_keytag
  # Step 2: generate NSEC3PARAM RR and its RRSIG
  ttl = 0
  NSEC3PARAMRR = ' '.join ( [zone.origin.derelativize(zone.origin).to_text(), 
    str(ttl),
    "IN NSEC3PARAM 1 1 10 AABBCCDD"])
  tok = dns.tokenizer.Tokenizer(NSEC3PARAMRR)
  name = tok.get_name()
  ttl = tok.get_ttl()
  rdclass = tok.get_string()
  rdtype = tok.get_string()
  tmpRR = dns.rdata.from_text(rdclass, rdtype, tok, origin=zone.origin)
  RRstr = ' '.join([name.to_text(), str(ttl), rdclass, rdtype, tmpRR.to_text()])
  signed_zone.append( RRstr )

  tmpRdataset = dns.rdataset.from_rdata_list( ttl, [tmpRR] )
  type_covered = int(dns.rdatatype.NSEC3PARAM)
  ownername = zone.origin
  labels = ownername.derelativize(zone.origin).to_text().count(".")
  original_ttl = ttl
  signer = zone.origin

  header = struct.pack('!HBBIIIH', type_covered,
           algorithm, labels,
           original_ttl, expiration,
           inception, key_tag)
  header += signer.to_wire()
  data = header + dns.dnssec.extract_unsigned_data( (ownername, tmpRdataset), key_tag, original_ttl, origin=zone.origin)
  Rdata = { 'type_covered': type_covered, 
    'rdatatype' :46,
    'algorithm' : int(dns.dnssec.Algorithm.SM2SM3),
    'labels' : labels,
    'original_ttl' : original_ttl,
    'expiration' : expiration,
    'inception' : inception,
    'key_tag' : key_tag,
    'signer' : signer
  }
  RRstr = generate_signature( ownername, RRdataset, Rdata, data, zsk_prikey, zsk_pubkey )
  signed_zone.append( RRstr )

  # Step 3: extract info for NSEC3 RR
  hnametypedic={}
  for ownername in nodes:
    rdatasets=zone.nodes[ownername]
    hashname=dns.dnssec.nsec3_hash(ownername.derelativize(zone.origin), 'AABBCCDD', 10, "SHA1")

    hnametypedic[hashname] = {}
    hnametypedic[hashname]['oname'] = ownername
    hnametypedic[hashname]['rrtypelist'] = []
    if ownername.derelativize(zone.origin) == zone.origin:
      # print("zone apex matched")
      hnametypedic[hashname]['rrtypelist'].append('NSEC3PARAM')
    for RRdataset in rdatasets:
      if RRdataset.rdtype ==  dns.rdatatype.NSEC3 or \
        RRdataset.rdtype ==  dns.rdatatype.NSEC or \
        RRdataset.rdtype ==  dns.rdatatype.NSEC3PARAM or \
        RRdataset.rdtype ==  dns.rdatatype.RRSIG:
        continue
      else:
        # print("non NSEC/NSEC3/RRSIG record")
        RRtype = dns.rdatatype.to_text(RRdataset.rdtype)
        hnametypedic[hashname]['rrtypelist'].append(RRtype)
    if not hnametypedic[hashname]['rrtypelist']:
      del(hnametypedic[hashname])
    else:
      hnametypedic[hashname]['rrtypelist'].append('RRSIG')

  # Step 4: construct hashname circle
  lastname = ''
  firstname = ''
  for hashname in sorted(hnametypedic):
    # print(lastname, hashname)
    if lastname == '':
      lastname = hashname
      firstname = hashname
    else:
      hnametypedic[lastname]['next'] = hashname
      lastname = hashname
  hnametypedic[hashname]['next'] = firstname

  # Step 5: generate NSEC3 RR and its RRSIG
  ttl = params['default_ttl']
  for hashname in sorted(hnametypedic):
    NSEC3RR = ' '.join ( [hashname, 
      str(ttl),
      "IN NSEC3 1 1 10 AABBCCDD (",
      hnametypedic[hashname]['next'], 
      ' '.join(hnametypedic[hashname]['rrtypelist']),
      ")"
      ])
    tok = dns.tokenizer.Tokenizer(NSEC3RR)
    name = tok.get_name()
    ttl = tok.get_ttl()
    rdclass = tok.get_string()
    rdtype = tok.get_string()
    tmpRR = dns.rdata.from_text(rdclass, rdtype, tok, origin=zone.origin)
    RRstr = ' '.join([hashname, str(ttl), rdclass, rdtype, tmpRR.to_text()])
    signed_zone.append( RRstr )

    tmpRdataset = dns.rdataset.from_rdata_list( ttl, [tmpRR] )
    type_covered = int(dns.rdatatype.NSEC3)
    algorithm = int(dns.dnssec.Algorithm.SM2SM3)
    ownername = dns.name.from_text(hashname, origin=zone.origin)
    labels = zone.origin.to_text().count(".")+1
    original_ttl = ttl
    signer = zone.origin

    header = struct.pack('!HBBIIIH', type_covered,
             algorithm, labels,
             original_ttl, expiration,
             inception, key_tag)
    header += signer.to_wire()
    data = header + dns.dnssec.extract_unsigned_data( (ownername, tmpRdataset), key_tag, original_ttl, origin=zone.origin)
    Rdata = { 'type_covered': type_covered, 
      'rdatatype' :46,
      'algorithm' : int(dns.dnssec.Algorithm.SM2SM3),
      'labels' : labels,
      'original_ttl' : original_ttl,
      'expiration' : expiration,
      'inception' : inception,
      'key_tag' : key_tag,
      'signer' : signer
    }
    RRstr = generate_signature( ownername, RRdataset, Rdata, data, zsk_prikey, zsk_pubkey )
    signed_zone.append( RRstr )

  return signed_zone

def readkey ( fkey ):
  '''
    read private key, public key and keytag from file.

    @param fkey  prefix of key file name.
      e.g. keys/Kexample.+017+56565
        .private file
          Algorithm: 17 (SM2SM3)
          PrivateKey: TrMxSFqYnhBqMmjIOO2KW9BjxILzPPgLeJ8CRamj3Eg=
        .key file
          example. IN DNSKEY 257 3 17 LV3Ts8kn7IBjBMEb019ur/5pe2JkraLLVvC0HdqQL+I7aSmteqLX8RNx+w0lLLQhJ1n6qqqGwZ7oQACq+0cTYA==
    @return  a list of private key, public key and keytag
  '''

  fn = fkey+'.private'
  f = open( fn, "r" )
  for line in f.readlines():
    line = line.strip()
    if line.startswith("Algorithm: "):
      (header, algorithm, other) = line.split(' ')
    elif line.startswith("PrivateKey: "):
      (header, prikey ) = line.split(' ')
  f.close()
  # prikey = base64.b64decode(prikey)

  fn = fkey+'.key'
  f = open( fn, "r" )
  for line in f.readlines():
    line = line.strip()
    if line.startswith(";") or line == "":
      pass
    else:
      pubkey = line.split(' ')[-1]
  f.close()
  # pubkey = base64.b64decode(pubkey)

  keytag = int(fkey.split('+')[-1])

  return ( prikey, pubkey, keytag )

def timetrans( timestr ):
  '''
    translate time of '%Y%m%d%H%M%S' format to timestamp
  '''
  str_to_time = datetime.datetime.strptime(timestr, '%Y%m%d%H%M%S')
  time_to_ts = int(time.mktime(str_to_time.timetuple()))
  return time_to_ts

if __name__ == "__main__":
  '''
    argv[0]: script
    argv[1]: zonename
    argv[2]: zonefile
    argv[3]: ksk keyfile prefix: Kexample.+017+56565
    argv[4]: zsk keyfile prefix: Kexample.+017+21907
    argv[5]: expiration
    argv[6]: inception
  '''
  parser = argparse.ArgumentParser()
  parser.add_argument("--zonename", "-o", help="zonename", required=True)
  parser.add_argument("--zonefile", "-f", help="zonefile", required=True)
  parser.add_argument("--ksk", "-k", help="ksk", required=True)
  parser.add_argument("--zsk", "-z", help="zsk", required=True)
  parser.add_argument("--expiration", "-e", help="type")
  parser.add_argument("--inception", "-s", help="type")
  args = parser.parse_args()
  # print(args)

  ORIGIN = args.zonename
  # sm2sm3_example.zone
  zonefile = args.zonefile 
  fksk = args.ksk
  fzsk = args.zsk

  ( ksk_prikey, ksk_pubkey, ksk_keytag ) = readkey( fksk )
  ( zsk_prikey, zsk_pubkey, zsk_keytag ) = readkey( fzsk )

  zone = dns.zone.from_file(zonefile, origin=ORIGIN)

  params = {
    'ksk_prikey' : ksk_prikey, 
    'ksk_pubkey' : ksk_pubkey,
    'ksk_keytag' : ksk_keytag,
    'zsk_prikey' : zsk_prikey, 
    'zsk_pubkey' : zsk_pubkey,
    'zsk_keytag' : zsk_keytag,
    'expiration' : timetrans(args.expiration),
    'inception'  : timetrans(args.inception),
    'default_ttl': 3600
  }
  # print(json.dumps(params, indent=2))
  params['ksk_prikey'] = base64.b64decode(ksk_prikey)
  params['ksk_pubkey'] = base64.b64decode(ksk_pubkey)
  params['zsk_prikey'] = base64.b64decode(zsk_prikey)
  params['zsk_pubkey'] = base64.b64decode(zsk_pubkey)

  signed_zone = generate_new_RRSIG( zone, params )
  fn = args.zonefile + '.signed'
  f = open( fn, 'w' )
  for line in signed_zone:
    f.write( line + '\n')
  f.close()
