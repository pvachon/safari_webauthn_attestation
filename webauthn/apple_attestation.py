from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import webauthn.utils
import json
import base64

kAPPLE_WEBAUTHN_AUTHORITY_ROOT_PEM = '''
-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----
    '''.encode('ascii')

# Decode the root so we can use it later
kAPPLE_WEBAUTHN_AUTHORITY_ROOT = x509.load_pem_x509_certificate(
        kAPPLE_WEBAUTHN_AUTHORITY_ROOT_PEM, default_backend())

# Apple OID for the nonce hash
kAPPLE_AAA_NONCE_OID = x509.ObjectIdentifier('1.2.840.113635.100.8.2')


def _generate_attest_nonce(auth_data_raw, client_data_raw):
    """
    Given the raw client data and auth data structures, calculate the
    nonce that is included as the subject in the attestation end
    entity cert.
    """

    # Hash the client data string
    client_digest = hashes.Hash(hashes.SHA256())
    client_digest.update(client_data_raw)

    # Concatenate with auth data
    concat = auth_data_raw + client_digest.finalize()

    # Generate nonce
    nonce_digest = hashes.Hash(hashes.SHA256())
    nonce_digest.update(concat)
    nonce = nonce_digest.finalize()

    return nonce


def check_attestation_apple(decoded, challenge, client_data_raw):
    """
    Given the parameters for this credential creation, verify that the
    provided decoded attestation blob contains a complete attestation
    chain that is rooted in the pinned Apple Webauthn Authority root CA.
    """
    # Extract the authenticator data
    if 'authData' not in decoded.keys():
        raise Exception('Missing authData key')
    auth_data_raw = decoded.get('authData')

    auth_data = webauthn.utils.decode_auth_data(auth_data_raw)

    attest_nonce = _generate_attest_nonce(auth_data_raw, client_data_raw)

    print(auth_data)

    # Make sure we have the required attributes
    if 'attStmt' not in decoded.keys():
        raise Exception('Missing attStmt key')

    # Decode the Attestation statement
    att_stmt = decoded.get('attStmt', {})
    if 'x5c' not in att_stmt.keys():
        raise Exception('Missing Cert Chain in attStmt')
    cert_chain_raw = att_stmt.get('x5c', [])

    # Load the unordered cert chain
    cert_chain = [x509.load_der_x509_certificate(cert, default_backend()) for cert in cert_chain_raw]

    for i in cert_chain:
        print(i)

    # TODO (big) - check that the EE cert chains up to our pinned root. If you
    # don't do this, the rest of these checks are useless.

    ee_cert = cert_chain[0]

    # Extract the magic Apple extension
    ee_exts = ee_cert.extensions
    ext = ee_exts.get_extension_for_oid(kAPPLE_AAA_NONCE_OID)

    # This gives us the raw extension. This still has a sequence of
    # 1 octet string embedded in it. For the sake of this hack, we just
    # lop it off. This only works because this field is always a full
    # SHA-256 hash.
    print(''.join('{:02x}'.format(x) for x in ext.value.value[6:]))
    print(''.join('{:02x}'.format(x) for x in attest_nonce))

    if ext.value.value[6:] != attest_nonce:
        raise Exception('Attestation nonce calculated does not match value in cert')

    # Now verify the user data contains the original nonce we shipped along
    client_data = json.loads(client_data_raw)
    print(client_data)

    if 'challenge' not in client_data:
        raise Exception('Client data is malformed, aborting.')

    # Note - the b64 returned challenge is URL-safe, and has the = padding
    # stripped. As a quick hack, append some extra padding - this 'just works'
    # because the Python base64 implementation discards remaining padding.
    client_data_challenge = base64.urlsafe_b64decode(client_data.get('challenge') + '===')

    if client_data_challenge != challenge:
        raise Exception('Challenge in client data object does not match what we originally sent, aborting.')

    # Check that the end entity certificate pubkey matches what we got from
    # the authenticator data blob
    auth_data_key = auth_data['attestedCredData']['credentialPublicKey']['key']
    if auth_data_key.public_numbers() != ee_cert.public_key().public_numbers():
        raise Exception('Public key in Auth Data and end entity cert do not match')

    return True

