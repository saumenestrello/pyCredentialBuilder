import json
import hashlib

from pycrypto.zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from pycrypto.zokrates_pycrypto.field import FQ
from pycrypto.zokrates_pycrypto.utils import write_signature_for_zokrates_cli
from pycrypto.zokrates_pycrypto.utils import pprint_hex_as_256bit
from bitstring import BitArray

#generate credential jwt
def generate_credential(iss,sub,cf,nationality):

    vc = {} #credential
    
    p = {} #payload
    h = {} #header
    pr = {} #proof
    
    csu = {}
    p["iss"] = iss
    p["sub"] = sub
    csu["cf"] = cf
    csu["nationality"] = nationality
    p["csu"] = csu

    h["typ"] = "JWT"
    h["alg"] = "EDDSA"

    vc["payload"] = p
    vc["header"] = h
    vc["signature"] = generate_signature(p)

    return vc
   
#generate EdDSA signature of the merkle root derived from the claims cf,nationality,sub and iss
def generate_signature(p):

    leaf1 = hashlib.sha512(p["csu"]["cf"].encode("utf-8")).hexdigest()
    leaf2 = hashlib.sha512(p["csu"]["nationality"].encode("utf-8")).hexdigest()
    leaf3 = hashlib.sha512(p["sub"].encode("utf-8")).hexdigest()
    leaf4 = hashlib.sha512(p["iss"].encode("utf-8")).hexdigest()
    
    subtree1 = hashlib.sha512(leaf1.encode("utf-8")+leaf2.encode("utf-8")).hexdigest()
    subtree2 = hashlib.sha512(leaf3.encode("utf-8")+leaf4.encode("utf-8")).hexdigest()

    merkle_root = hashlib.sha512(subtree1.encode("utf-8")+subtree2.encode("utf-8")).digest()

    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(merkle_root)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, merkle_root)
    print(is_verified)

    path = 'zokrates_inputs.txt'
    #write_signature_for_zokrates_cli(pk, sig, merkle_root, path)

    sig_to_export = write_sig(pk,sig,merkle_root)

    return sig_to_export

#convert signature in a Zokrates-friendly shape
def write_sig(pk, sig, msg):

    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = " ".join(map(str, args))

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = BitArray(int(M0, 16).to_bytes(32, "big")).bin
    b1 = BitArray(int(M1, 16).to_bytes(32, "big")).bin
    args = args + " " + " ".join(b0 + b1)

    return args


#entry point - load input parameters from file

with open('config.json') as f_input:
  data = json.load(f_input)
  
iss = data["iss"]
sub = data["sub"]
cf = data["cf"]
nationality = data["nationality"]

v = generate_credential(iss,sub,cf,nationality)

print(v)

#export generated verifiable credential
with open('jwt.json', 'w') as outfile:
    json.dump(v, outfile, indent=4, sort_keys=True)
