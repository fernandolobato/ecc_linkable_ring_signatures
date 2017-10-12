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
import sha3
import functools
import ecdsa

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1

def ring_signature(siging_key, key_idx, M, y, G=SECP256k1.generator, hash_func=sha3.keccak_256):
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

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

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
    H = H2(y, hash_func=hash_func)
    Y =  H * siging_key

    # STEP 2
    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = H1([y, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:
        
        s[i] = randrange(SECP256k1.order)
        
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([y, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order
    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator, hash_func=sha3.keccak_256):
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

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

        RETURNS
        -------
            Boolean value indicating if signature is valid.

    """
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    H = H2(y, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([y, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == H1([y, Y, message, z_1, z_2], hash_func=hash_func)

    return False


def map_to_curve(x):
    """ 
        Maps an integer to an elliptic curve.
    """
    return SECP256k1.generator * x


def H1(msg, hash_func=sha3.keccak_256):
    """ 
        Return an integer representation of the hash of a message. The 
        message can be a list of messages that are concatenated with the
        concat() function.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) a hash function which can recieve an input
                string and return a hexadecimal digest.

        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)


def H2(msg, hash_func=sha3.keccak_256):
    """
        Hashes a message into an elliptic curve point.
    
        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.
            
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.  
    """
    return map_to_curve(H1(msg, hash_func=hash_func))


def concat(params):
    """
        Concatenates a list of parameters into a bytes. If one
        of the parameters is a list, calls itself recursively.

        PARAMS
        ------
            params: (list) list of elements, must be of type:
                - int
                - list
                - str
                - ecdsa.ellipticcurve.Point

        RETURNS
        -------
            concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):
        
        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()


    return functools.reduce(lambda x, y: x + y, bytes_value)


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