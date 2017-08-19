import pkg_resources

from phe.encoding import EncodedNumber
from phe.paillier import generate_paillier_keypair
from phe.paillier import EncryptedNumber
from phe.paillier import PaillierPrivateKey, PaillierPublicKey
from phe.paillier import PaillierPrivateKeyring

import phe.util

try:
    import phe.command_line
except ImportError:
    pass

__version__ = pkg_resources.get_distribution('phe').version
__author__ = 'N1 Analytics'
