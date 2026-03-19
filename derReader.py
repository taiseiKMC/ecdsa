from pyasn1.type.namedtype import NamedType, NamedTypes, DefaultedNamedType, OptionalNamedType
from pyasn1.type.univ import Integer, Sequence, BitString, OctetString, ObjectIdentifier
from pyasn1.type import tag
from pyasn1.codec.der.decoder import decode
from edcsa import byteToInt

# RFC 5915: ECPrivateKey for ECDSA
class ECPrivateKey(Sequence):
    componentType = NamedTypes(
        NamedType('version', Integer()),
        NamedType('privateKey', OctetString()),
        OptionalNamedType('parameters', ObjectIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        OptionalNamedType('publicKey', BitString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )

# RFC 5480: AlgorithmIdentifier for ECDSA with SHA-256
class AlgorithmIdentifier(Sequence):
    componentType = NamedTypes(
        NamedType('algorithm', ObjectIdentifier()),
        OptionalNamedType('parameters', ObjectIdentifier())
    )

# RFC 5480: SubjectPublicKeyInfo for ECDSA public key
class SubjectPublicKeyInfo(Sequence):
    componentType = NamedTypes(
        NamedType('algorithm', AlgorithmIdentifier()),
        NamedType('subjectPublicKey', BitString())
    )

class EcdsaSignature(Sequence):
    componentType = NamedTypes(
        NamedType('r', Integer()),
        NamedType('s', Integer())
    )

EcdsaPublic = SubjectPublicKeyInfo
EcdsaPrivate = ECPrivateKey

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
        pub_asn1, _ = decode(pub, asn1Spec=SubjectPublicKeyInfo())
    # Extract public key bits (0x04 || X || Y)
    bits = pub_asn1.getComponentByName('subjectPublicKey').asOctets()
    # bits[0] = 0x04 (uncompressed indicator)
    # bits[1:33] = X coordinate
    # bits[33:65] = Y coordinate
    x = byteToInt(bits[1:33])
    y = byteToInt(bits[33:65])
    return x, y

def parsePrivateKey(filename):
    with open(filename, "rb") as f:
        priv = f.read()
        priv_asn1, _ = decode(priv, asn1Spec=ECPrivateKey())
    # Extract private key scalar
    private_key_bytes = priv_asn1.getComponentByName('privateKey').asOctets()
    d = byteToInt(private_key_bytes)
    
    # Optionally extract public key if present
    public_key_bits = priv_asn1.getComponentByName('publicKey')
    if public_key_bits is not None:
        bits = public_key_bits.asOctets()
        x = byteToInt(bits[1:33])
        y = byteToInt(bits[33:65])
        return d, (x, y)
    else:
        return d, None
