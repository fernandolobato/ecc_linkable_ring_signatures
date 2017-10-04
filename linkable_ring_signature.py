"""
"""
import hashlib

from ecdsa import keys
from ecdsa.util import randrange
from ecdsa.curves import SECP256k1

def ring_signature(siging_key, key_idx, M, y, G=SECP256k1.generator):
    """
    """
    n = len(y)
    c = [0] * n
    s = [0] * n
    next_idx = lambda i: (i + 1) % n

    # STEP 1
    L = to_str(y)
    H = H2(L)
    Y =  H * siging_key

    # STEP 2
    u = randrange(SECP256k1.order)
    c[next_idx(key_idx)] = H1([L, Y, M, G * u, H * u])

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:
        
        s[i] = randrange(SECP256k1.order)
        
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[ next_idx(i) ] = H1([L, Y, M, z_1, z_2])

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order

    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator):
    """
        Verifies if a valid signature was made by a key inside a set of keys.
    

        PARAMS
        ------
            message: (str) message being verified.

            y: (list) set of public keys with which the message was signed.

            c_0: (int) initial value to reconstruct the ring.


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
            return c_0 == H1([L, Y, message, z_1, z_2])

    return False


def map_to_curve(x):
    """
    """
    return SECP256k1.generator * x


def H1(msg, base=16, hash_func=hashlib.sha256):
    """
    """
    return int(hash_func(to_str(msg).encode('utf-8')).hexdigest(), base)


def H2(msg):
    """
    """
    return map_to_curve(H1(msg))


def to_str(params):
    """ Concatenate a list of parameters of type string, integer and ecdsa.ellipticcurve.Point
        into a string without spaces. 
    """
    return ''.join(list(map(lambda p: str(p) if type(p) in [int, str] else str(p.x()) + str(p.y()), params)))


def main(): 
    number_participants = 5

    x = [ randrange(SECP256k1.order) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator * xi, x))

    message = "Every move we made was a kiss"

    i = 2
    signature = ring_signature(x[i], i, message, y)

    assert(verify_ring_signature(message, y, *signature))

if __name__ == '__main__':
    main()