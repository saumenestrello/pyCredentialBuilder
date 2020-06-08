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
    csu = {} #csu

    #build payload 
    p["iss"] = iss
    p["sub"] = sub
    csu["cf"] = cf
    csu["nationality"] = nationality
    p["csu"] = csu

    #build header
    h["typ"] = "JWT"
    h["alg"] = "EDDSA"

    #build credential
    vc["payload"] = p
    vc["header"] = h
    s,export = generate_signature(p)
    vc["signature"] = s

    return vc,export
   
#generate EdDSA signature of the merkle root derived from the claims cf,nationality,sub and iss
def generate_signature(p):

    #keys
    leaf1_key = hashlib.sha512("cf:".encode("utf-8")).hexdigest()
    leaf2_key = hashlib.sha512("nationality:".encode("utf-8")).hexdigest()
    leaf3_key = hashlib.sha512("sub:".encode("utf-8")).hexdigest()
    leaf4_key = hashlib.sha512("iss:".encode("utf-8")).hexdigest()

    #plaintxt leaves
    #leaf1_plaintxt = leaf1_key + p["csu"]["cf"]
    #leaf2_plaintxt = leaf2_key + p["csu"]["nationality"]
    #leaf3_plaintxt = leaf3_key + p["sub"]
    #leaf4_plaintxt = leaf4_key + p["iss"]

    leaf1_value = hashlib.sha512(p["csu"]["cf"].encode("utf-8")).hexdigest()
    leaf2_value = hashlib.sha512(p["csu"]["nationality"].encode("utf-8")).hexdigest()
    leaf3_value = hashlib.sha512(p["sub"].encode("utf-8")).hexdigest()
    leaf4_value = hashlib.sha512(p["iss"].encode("utf-8")).hexdigest()

    #hashed leaves
    #leaf1 = hashlib.sha512(leaf1_plaintxt.encode("utf-8")).hexdigest()
    #leaf2 = hashlib.sha512(leaf2_plaintxt.encode("utf-8")).hexdigest()
    #leaf3 = hashlib.sha512(leaf3_plaintxt.encode("utf-8")).hexdigest()
    #leaf4 = hashlib.sha512(leaf4_plaintxt.encode("utf-8")).hexdigest()

    leaf1 = hashlib.sha512((leaf1_key+leaf1_value).encode("utf-8")).hexdigest()
    leaf2 = hashlib.sha512((leaf2_key+leaf2_value).encode("utf-8")).hexdigest()
    leaf3 = hashlib.sha512((leaf3_key+leaf3_value).encode("utf-8")).hexdigest()
    leaf4 = hashlib.sha512((leaf4_key+leaf4_value).encode("utf-8")).hexdigest()

    #tree lvl 1
    subtree1 = hashlib.sha512(leaf1.encode("utf-8")+leaf2.encode("utf-8")).hexdigest()
    subtree2 = hashlib.sha512(leaf3.encode("utf-8")+leaf4.encode("utf-8")).hexdigest()

    merkle_root = hashlib.sha512(subtree1.encode("utf-8")+subtree2.encode("utf-8")).digest()

    #sign merkle root
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(merkle_root)

    #verify signature
    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, merkle_root)
    print(is_verified)

    path = 'zokrates_inputs.txt'
    write_signature_for_zokrates_cli(pk, sig, merkle_root, path)

    sig_to_export = write_sig(pk,sig,merkle_root)

    #export zokrates circuit inputs
    obj = {}
    obj_pk = {}
    obj_sig = {}

    obj_pk["x"] = str(pk.p.x)
    obj_pk["y"] = str(pk.p.y) 
    obj["pk"] = obj_pk
    #obj["treeDepth"] = 2
    obj["merkleRoot"] = hashlib.sha512(subtree1.encode("utf-8")+subtree2.encode("utf-8")).hexdigest()
    obj["leafKey"] = hashlib.sha512(leaf1_key.encode("utf-8")).hexdigest()
    obj["leafValue"] = hashlib.sha512(p["csu"]["cf"].encode("utf-8")).hexdigest()
    #obj["directionSelector"] = 0
    obj["pathDigest0"] = subtree2

    sig_R, sig_S = sig
    
    obj_R = {}  
    obj_R["x"] = str(sig_R.x)
    obj_R["y"] = str(sig_R.y)

    obj_sig["R"] = obj_R
    obj_sig["S"] = sig_S

    obj_A = {}  
    obj_A["x"] = pk.p.x.n
    obj_A["y"] = pk.p.y.n
    obj_sig["A"] = obj_A

    obj_sig["M0"] = merkle_root.hex()[:64]
    obj_sig["M1"] = merkle_root.hex()[64:]

    b0 = BitArray(int(obj_sig["M0"], 16).to_bytes(32, "big")).bin
    b1 = BitArray(int(obj_sig["M1"], 16).to_bytes(32, "big")).bin

    obj_sig["context"] = b0 + b1
    
    obj["signature"] = obj_sig

    vcSignature = {}
    vcSignature["R"] = sig_R.__str__()
    vcSignature["S"] = sig_S.__str__()

    return vcSignature,obj

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

v,export = generate_credential(iss,sub,cf,nationality)

print(v)
print(export)

#export generated verifiable credential
with open('jwt.json', 'w') as outfile:
    json.dump(v, outfile, indent=4, sort_keys=True)

#export zokrates circuit input parameters
with open('params.json', 'w') as outfile2:
    json.dump(export, outfile2, indent=4, sort_keys=True)
