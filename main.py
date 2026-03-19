from edcsa import secp256k1
from derReader import parsePublicKey, parseSignature

if __name__ == "__main__":
    sign, verify, generateKeyPair, Fp, Fn, EcPoint = secp256k1()

    with open("message.txt", "r") as f:
        msg = f.read().encode()

    r, s = parseSignature("sig.der")
    r = Fn(r)
    s = Fn(s)

    pubx, puby = parsePublicKey("pubkey.der")
    public_key = EcPoint(Fp(pubx), Fp(puby))
    if verify(msg, (r, s), public_key):
        print("Signature is valid")
    else:
        print("Signature is invalid")
