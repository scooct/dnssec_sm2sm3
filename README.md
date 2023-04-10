# dnssec_sm2sm3
sign and validate dnssec signature with sm2sm3 algorithm

## Requirements
    Python 3.6.15
    dnspython 2.2.1
    gmssl https://github.com/smdll/crypto-gmssl/tree/master/gmssl

## Example
    UNSIGNED=sm2sm3_example.zone
    python3 keygen.py -o example -k ksk
    python3 keygen.py -o example -k zsk
    python3 dsfromkey.py keys/Kexample.+017+56565.key
    cat keys/Kexample.+017+56565.key keys/Kexample.+017+21907.key >> ${UNSIGNED}
    python3 signzone.py -e 20240401000000 -s 20230401000000 -o example -f ${UNSIGNED} -k keys/Kexample.+017+56565 -z keys/Kexample.+017+21907
    python3 validatezone.py -o example -f sm2sm3_example.zone.signed.wrong.1
    python3 validatezone.py -o example -f ${UNSIGNED}.signed

## Notation
In order to support SM2SM3 algorithm, the file dnssec.py of dnspython was modified accordingly. The patch file could be found in deps/dnssec.py.patch<br>

    patch -p0 < dnssec.py.patch
    
