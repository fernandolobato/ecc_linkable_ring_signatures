#! /usr/bin/env python
#
# Provide an implementation of Linkable Spontaneus Anonymous Group Signature
# over elliptic curve cryptography. 
#
# Implementation of cryptographic scheme from: https://eprint.iacr.org/2004/027.pdf
# 
#
# Written in 2017 by Fernanddo Lobato Meeser and placed in the public domain.

import hashlib

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1

def ring_signature(siging_key, key_idx, M, y, G=SECP256k1.generator):
    """ 
        Generates a ring signature for a message given a specific set of
        public keys and a signing key belonging to one of the public keys
        in the set.

        PARAMS
        ------

            signing_key: (int) The with which the message is to be anonymously signed.

            key_idx: (int) The index of the public key corresponding to the signature
                private key over the list of public keys that compromise the signature.

            M: (str) Message to be signed.

            y: (list) The list of public keys which over which the anonymous signature
                will be compose.

            G = (ecdsa.ellipticcurve.Point) Generator point for the elliptic curve.
        
        RETURNS
        -------

            Signature (c_0, s, Y) :
                c_0: Initial value to reconstruct signature.
                s = vector of randomly generated values with encrypted secret to 
                    reconstruct signature.
                Y = Link for current signer.

    """
    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1
    L = to_str(y)
    H = H2(L)
    Y =  H * siging_key

    # STEP 2
    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = H1([L, Y, M, G * u, H * u])

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:
        
        s[i] = randrange(SECP256k1.order)
        
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([L, Y, M, z_1, z_2])

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order

    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator):
    """
        Verifies if a valid signature was made by a key inside a set of keys.
    

        PARAMS
        ------
            message: (str) message whos' signature is being verified.
            
            y: (list) set of public keys with which the message was signed.

            Signature:
                c_0: (int) initial value to reconstruct the ring.

                s: (list) vector of secrets used to create ring.

                Y = (int) Link of unique signer.

            G = (ecdsa.ellipticcurve.Point) Generator point for the elliptic curve.


        RETURNS
        -------
            Boolean value indicating if signature is valid.

    """
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    L = to_str(y)
    H = H2(L)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([L, Y, message, z_1, z_2])
        else:
            # Did we correctly reconstruct ring?
            return c_0 == H1([L, Y, message, z_1, z_2])

    return False


def map_to_curve(x):
    """ Maps an integer to an elliptic curve.
    """
    return SECP256k1.generator * x


def H1(msg, hash_func=hashlib.sha256):
    """ Return an integer representation of the hash of a message. The 
        message can be a list of messages that are concatenated with the
        to_str() function.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) a hash function which can recieve an input
                string and return a hexadecimal digest.

        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """
    return int(hash_func(to_str(msg).encode('utf-8')).hexdigest(), 16)


def H2(msg):
    """ Hashes a message into an elliptic curve point.
    
        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.  
    """
    return map_to_curve(H1(msg))


def to_str(params):
    """ Concatenate a list of parameters of type string, integer and ecdsa.ellipticcurve.Point
        into a string without spaces. 
    """
    return ''.join(list(map(lambda p: str(p) if type(p) in [int, str] else str(p.x()) + str(p.y()), params)))


def main(): 
    number_participants = 10

    x = [ randrange(SECP256k1.order) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator * xi, x))

    message = "Every move we made was a kiss"

    i = 2
    signature = ring_signature(x[i], i, message, y)

    assert(verify_ring_signature(message, y, *signature))

if __name__ == '__main__':
    main()