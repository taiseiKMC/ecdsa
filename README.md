# ECDSA

ECDSA の一種, secp256k1 の実装

```
% echo "Hello, World!" > message.txt
% openssl ecparam -genkey -name secp256k1 -outform DER -out key.der
% openssl ec -in key.der -inform DER -pubout -outform DER -out pubkey.der
% openssl dgst -sha256 -sign key.der -keyform DER -out sig.der message.txt
% python main.py
```

# References
* [ASN.1 と DER へようこそ](https://letsencrypt.org/ja/docs/a-warm-welcome-to-asn1-and-der/)
* [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)
* [ECDSA and DER Signatures](https://github.com/libbitcoin/libbitcoin-system/wiki/ECDSA-and-DER-Signatures)
* [クラウドを支えるこれからの暗号技術](https://raw.githubusercontent.com/herumi/ango/master/ango.pdf)
