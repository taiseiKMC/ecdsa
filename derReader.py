from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.univ import Integer, Sequence, BitString
from pyasn1.codec.der.decoder import decode
from edcsa import byteToInt

# der encoding for ECDSA signature
class EcdsaSignature(Sequence):
    componentType = NamedTypes(
        NamedType('r', Integer()),
        NamedType('s', Integer())
    )

# der encoding for ECDSA public key
class EcdsaPublic(Sequence):
    componentType = NamedTypes(
        # Identifiers for ECDSA with SHA-256 and for secp256k1
        NamedType('_', Sequence()),
        # 0x04 || X || Y
        NamedType('p', BitString())
    )

def parseSignature(filename):
    with open(filename, "rb") as f:
        sig = f.read()
        sig_asn1, _ = decode(sig, asn1Spec=EcdsaSignature())
    r = int(sig_asn1.getComponentByName('r'))
    s = int(sig_asn1.getComponentByName('s'))
    return r, s

def parsePublicKey(filename):
    with open(filename, "rb") as f:
        pub = f.read()
        pub_asn1, _ = decode(pub, asn1Spec=EcdsaPublic())
    bytes = pub_asn1.getComponentByName('p').asOctets()
    x = byteToInt(bytes[1:33])
    y = byteToInt(bytes[33:])
    return x, y
