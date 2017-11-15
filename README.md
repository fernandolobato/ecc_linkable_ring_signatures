# Linkable Spontaneous Anonymous Group Signature with Elliptic Curve Cryptograhpy.


Minimalistic pythonic implementation of a [linkable spontaneously anonymous group (LSAG)
signature scheme](https://eprint.iacr.org/2004/027.pdf) over elliptic curves.

With this package you can perform a ring signature over a set of public key without revealing which corresponding private key to one of the public keys in the set generated the signature.

This implementation was adapted from finte groups to elliptic curves. The scheme uses a cryptographic function as a random oracle to map numbers into the finit group. This implementation took the random oracle model by hashing into an elliptic curve using the 'Try-and-Increment' Method. More information can be found on [How to hash into Elliptic Curves](https://eprint.iacr.org/2009/226.pdf).

This implementation serves as a proof of concept. DO NOT TRY TO USE THIS FOR ANY REAL USE CASE. THIS HAS NOT BEEN TESTED EXTERNALLY.


Sign and verify a message:

```python

from linkable_ring_signature import ring_signature, verify_ring_signature

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1

number_participants = 10

x = [ randrange(SECP256k1.order) for i in range(number_participants)]
y = list(map(lambda xi: SECP256k1.generator * xi, x))

message = "Every move we made was a kiss"

i = 2
signature = ring_signature(x[i], i, message, y)

assert(verify_ring_signature(message, y, *signature))

```


### Stuff used to make this:

 * [ECDSA](https://github.com/warner/python-ecdsa) ECDSA cryptography python library. 
