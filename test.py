
import unittest

from edcsa import makeModClass, secp256k1

ModNum = makeModClass(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)

class TestModNum(unittest.TestCase):
    def test_add(self):
        self.assertEqual((ModNum(2) + ModNum(3)).v, 5)
    def test_neg(self):
        self.assertEqual((-ModNum(2)).v, ModNum.p - 2)
    def test_mul(self):
        self.assertEqual((ModNum(2) * ModNum(3)).v, 6)
        self.assertEqual((ModNum(-1) * ModNum(-2)).v, 2)

    def test_div(self):
        self.assertEqual((ModNum(6) // ModNum(3)).v, 2)
    def test_pow(self):
        self.assertEqual((ModNum(2) ** 3).v, 8)
        self.assertEqual((ModNum(2) ** 11).v, 2048)


class TestPoint(unittest.TestCase):
    _, _, _, Fp, Fn, EcPoint = secp256k1()
    x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    G = EcPoint(Fp(x), Fp(y))
    def test_mul1(self):
        G = self.G
        p = 2 * G
        q = G + G
        assert p == q

    def test_mul2(self):
        G = self.G
        a = 1021
        b = 65535
        p = a * G
        q = b * G
        assert b * p == a * q

class TestEcdsa(unittest.TestCase):
    def test_sign_verify(self):
        sign, verify, generateKeyPair, _, _, _ = secp256k1()
        private_key, public_key = generateKeyPair()

        msg = b"Hello, world!\n"
        sig = sign(msg, private_key)
        assert verify(msg, sig, public_key)

        (r, s) = sig
        sig = (r, - s) # (r, n - s) is also a valid signature
        assert verify(msg, sig, public_key)

if __name__ == "__main__":
    unittest.main()
