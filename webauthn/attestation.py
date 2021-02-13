import webauthn.apple_attestation

import cbor

def check_attestation(raw, challenge, client_data_raw, user_data):
    '''
    Decode the initial CBOR attestation result, and figure out which
    attestation plugin to use.
    '''
    decode = cbor.loads(raw)

    result = False

    if decode['fmt'] == 'apple':
        print('We have an Apple attestation statement')
        try:
            result = webauthn.apple_attestation.check_attestation_apple(decode, challenge, client_data_raw)
        except Exception as e:
            # If we see an exception, just fail the attestation
            print('Error: {}'.format(e))
            return False
    else:
        print('We have an unknown attestation statement kind')

    return result
