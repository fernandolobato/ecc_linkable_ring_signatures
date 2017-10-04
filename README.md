# Linkable Spontaneous Anonymous Group Signature with Elliptic Curve Cryptograhpy.


Minimalistic implementation of a [linkable spontaneously anonymous group (LSAG)
signature scheme](https://eprint.iacr.org/2004/027.pdf) with python over elliptic curves.

This implementation serves as a proof of concept. DO NOT TRY TO USE THIS FOR ANY REAL USE CASE. THIS HAS NOT BEEN TESTED EXTERNALLY.

TODO:
    The scheme requires to hash into an elliptic curve. This has not yet been implemented. Currently the scheme only multiplies the hash of the string being
    hashed by the EC generator.


Sing and verify a message:

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
