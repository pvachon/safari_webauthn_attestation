import struct
import cbor
import enum
from cryptography.hazmat.primitives.asymmetric import ec


class COSEKty(enum.Enum):
    OKP = 1
    ECP = 2
    Symmetric = 3


class COSEAlg(enum.Enum):
    ecc = -7
    rsa = -37


class COSEECCurves(enum.Enum):
    P256 = 1
    P384 = 2
    P521 = 3
    X25519 = 4
    X448 = 5
    Ed25519 = 6
    Ed448 = 7


def _decode_auth_data_cose(key_raw):
    """
    This is a very incomplete COSE -> JWK conversion function. Because,
    hey, why don't we have even more standards to represent keys.
    """
    key_unadorned = cbor.loads(key_raw)
    key_adorned = {}

    for k, v in key_unadorned.items():
        if k == 1:
            key_adorned['kty'] = COSEKty(v).name
        elif k == 3:
            key_adorned['alg'] = COSEAlg(v).name
        elif k == -1:
            key_adorned['eccurve'] = COSEECCurves(v).name
        elif k == -2:
            key_adorned['x'] = v
        elif k == -3:
            key_adorned['y'] = v
        else:
            key_adorned[k] = v

    # Create a pyca cryptography public key from this mess
    if key_adorned['alg'] == COSEAlg.ecc.name and key_adorned['eccurve'] == COSEECCurves.P256.name:
        x = int.from_bytes(key_adorned['x'], byteorder='big')
        y = int.from_bytes(key_adorned['y'], byteorder='big')
        nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        key_adorned['key'] = nums.public_key()
    return key_adorned


def decode_auth_data(raw):
    """
    Decode basic auth data from the authenticator. Note that this function
    will fail if there's extension data included in the basic auth data blob.
    This format sucks, and I want to help whoever designed this do a better
    job.
    """
    basic_auth_data = {
            'rpIdHash': raw[0:31],
            'flagsRaw': raw[32],
            'flags': {
                'userPresent': raw[32] & 0x1 != 0,
                'userVerified': raw[32] & 0x4 != 0,
                'attestedCredDataIncluded': raw[32] & 0x40 != 0,
                'extensionDataIncluded': raw[32] & 0x80 != 0,
            },
            'signCount': struct.unpack('>L', raw[33:37])[0],
        }
    if basic_auth_data['flags']['attestedCredDataIncluded']:
        acd_raw = raw[37:]
        credential_id_len = struct.unpack('>H', acd_raw[16:18])[0]

        basic_auth_data['attestedCredData'] = {
                'aaguid': acd_raw[0:15],
                'credentialIdLength': credential_id_len,
                'credentialId': acd_raw[18:18 + credential_id_len],
                'credentialPublicKey': _decode_auth_data_cose(acd_raw[18 + credential_id_len:]),
            }
    return basic_auth_data
