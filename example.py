import os

from linkable_ring_signature import ring_signature, verify_ring_signature

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1


def stringify_point(p):
    return '{},{}'.format(p.x(), p.y())

def stringify_point_js(p):
    return 'new BigNumber("{}"), new BigNumber("{}")'.format(p.x(), p.y())

def export_signature(y, message, signature, foler_name='./data', file_name='signature.txt'):
    """
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    S = ''.join(map(lambda x: str(x) + ',', signature[1]))[:-1]
    Y = stringify_point(signature[2])

    dump = '{}\n'.format(signature[0])
    dump += '{}\n'.format(S)
    dump += '{}\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: stringify_point(yi) + ';', y))[:-1]
    data = '{}\n'.format(message)
    data += '{}\n,'.format(pub_keys)[:-1]
    
    arch.write(data)
    arch.close()

def export_private_keys(s_keys, foler_name='./data', file_name='secrets.txt'):
    """
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    
    for key in s_keys:
        arch.write('{}\n'.format(key))

    arch.close()

def export_signature_javascript(y, message, signature, foler_name='./data', file_name='signature.js'):
    """
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')

    S = ''.join(map(lambda x: 'new BigNumber("' + str(x) + '"),', signature[1]))[:-1]
    Y = stringify_point_js(signature[2])

    dump = 'var c_0 = new BigNumber("{}");\n'.format(signature[0])
    dump += 'var s = [{}];\n'.format(S)
    dump += 'var Y = [{}];\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: stringify_point_js(yi) + ',', y))[:-1]

    data = 'var message = "{}";\n'.format(message)
    data += 'var pub_keys = [{}];'.format(pub_keys)

    arch.write(data + '\n')
    arch.close()

def main():
    number_participants = 4

    x = [ randrange(SECP256k1.order) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator * xi, x))

    message = "Every move we made was a kiss"

    i = 2
    signature = ring_signature(x[i], i, message, y)

    export_signature(y, message, signature)
    export_signature_javascript(y, message, signature)
    export_private_keys(x)

if __name__ == '__main__':
    main()