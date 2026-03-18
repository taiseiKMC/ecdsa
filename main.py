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

# 3056
# 3010
# 06072a8648ce3d0201 :Identifier for ECDSA with SHA-256
# 06052b8104000a :Identifier for secp256k1
# 0342
# 0004
# a9e0e0e342d17c21c55f76cf8436ea358adb81bc5b6471d67b852d72202c43b0
# bf5bf69f38f58596b283e99ba9024f414eda5da08d3631474766c73b5c918680


# 3074
# 0201 01
# 0420 b95e1fc38c707885153c7a7efc61d4d02346b4345df253cdadc1a6200518eb52
# a007 06052b8104000a
# a144 034200 0437c25a0accbe003e6699db5f0d12025f9e93d9c5cf718b31588cfb39fae58a0
#             62f304c17a924a5bf6e948544d599d4682d9e3d48b825e83ee52267f7fd65e41c
