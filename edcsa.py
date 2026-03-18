from __future__ import annotations
import secrets
from hashlib import sha256

def byteToInt(b):
    v = 0
    for x in b:
        v = (v << 8) + x
    return v

def makeModClass(q):
    class ModNum:
        p = q
        def __init__(self, v):
            self.v = v % ModNum.p

        def __eq__(self, rhs):
            return self.v == rhs.v

        def __neg__(self):
            return ModNum(-self.v)

        def __add__(self, rhs: ModNum):
            return ModNum(self.v + rhs.v)

        def __sub__(self, rhs: ModNum):
            return ModNum(self.v - rhs.v)

        def __mul__(self, rhs):
            if isinstance(rhs, int):
                return ModNum(self.v * rhs)
            if isinstance(rhs, ModNum):
                return ModNum(self.v * rhs.v)
            # delegate to rhs.__rmul__ for EcPoint or other types
            return NotImplemented

        def __truediv__(self, rhs: ModNum):
            return self * rhs.inv()
        
        def __pow__(self, exp : int):
            if exp == 0:
                return ModNum(1)
            elif exp % 2 == 0:
                ret = self.__pow__(exp >> 1)
                ret = ret * ret
            else:
                ret = self.__pow__(exp >> 1)
                ret = ret * ret * self
            return ret

        def inv(self):
            return self.__pow__(ModNum.p - 2)
        
        def __floordiv__(self, rhs):
            if isinstance(rhs, int):
                rhs = ModNum(rhs)
            return self * rhs.inv()
        
        def __str__(self):
            return hex(self.v)

    return ModNum

###
### Elliptic curve domain parameters
### p : Specifies prime field
### a, b: coefficients of the elliptic curve equation y^2 = x^3 + a*x + b
### gx, gy: coordinates of the base point G
### n : order of the base point G
### #E(Fp)/n = 1
###
def makeEc(p, a, b, gx, gy, n):
    Fp = makeModClass(p)
    Fn = makeModClass(n)

    class EcPoint:
        def __init__(self, x : Fp, y : Fp):
            self.x = x
            self.y = y
            assert self.isValid()
        
        def isValid(self):
            return self.y * self.y == self.x * self.x * self.x + Fp(a) * self.x + Fp(b)

        def __eq__(self, rhs):
            if isinstance(rhs, ZeroPoint):
                return False
            return self.x == rhs.x and self.y == rhs.y

        def __neg__ (self):
            return EcPoint(self.x, -self.y)

        def __add__(self, rhs: EcPoint):
            if isinstance(rhs, ZeroPoint):
                return self
            if self.x == rhs.x:
                if self.y == -rhs.y:
                    return ZeroPoint()
                # 接線
                l = (Fp(3) * self.x ** 2 + Fp(a)) / (Fp(2) * self.y)
            else:
                l = (rhs.y - self.y) / (rhs.x - self.x)
            
            # Viète's formula
            x3 = l ** 2 - self.x - rhs.x
            #y3 = l * (x3 - self.x) + self.y
            y3 = l * (self.x - x3) - self.y
            return EcPoint(x3, y3)
        
        ### only define Fn * Point, not Point * Fn.
        def __rmul__(self, k):
            if isinstance(k, Fn):
                k = k.v
            if k == 0:
                return ZeroPoint()
            elif k % 2 == 0:
                ret = self.__rmul__(k >> 1)
                ret = ret + ret
            else:
                ret = self.__rmul__(k >> 1)
                ret = ret + ret + self
            return ret

    class ZeroPoint(EcPoint):
        def __init__(self):
            pass
        def __eq__(self, rhs):
            return isinstance(rhs, ZeroPoint)
        def __neg__ (self):
            return self
        def __add__(self, rhs):
            return rhs
        
    G = EcPoint(Fp(gx), Fp(gy))

    def sign(msg : bytes, private_key : Fn, k : Fn = None):
        if k is None:
            # if k is given, use it instead of random k. This is for testing only.
            k = Fn(secrets.randbelow(n - 1) + 1)

        hash = byteToInt(sha256(msg).digest())
        kg = k * G
        r = Fn(kg.x.v)
        s = (Fn(hash) + private_key * r) / k
        if r == Fn(0) or s == Fn(0):
            # regenerate k and try again if r or s is 0, since that would leak the private key.
            return sign(msg, private_key)
        return (r, s)

    def verify(msg : bytes, signature : tuple[Fn, Fn], public_key : EcPoint):
        r, s = signature
        hash = byteToInt(sha256(msg).digest())
        a = (Fn(hash) / s) * G
        b = (r / s) * public_key
        c = a + b
        return c.x == r

    def generateKeyPair():
        private_key = Fn(secrets.randbelow(n - 1) + 1)
        public_key = private_key * G
        return private_key, public_key
    
    return sign, verify, generateKeyPair, Fp, Fn, EcPoint

# secp256k1 instance
def secp256k1():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = 0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    a = 0
    b = 7
    return makeEc(p, a, b, x, y, n)
