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