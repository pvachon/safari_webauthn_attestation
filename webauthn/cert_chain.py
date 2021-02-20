#!/usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def check_cert_chain(chain, root):
    """
    Given a certificate chain and a pinned root certificate, validate that:
    a) The end entity chains all the way up to the given root
    b) All certificates are required to create the chain
    """
    valid = []

    cert = chain.pop(0)
    while chain:
        cert_next = chain.pop(0)

        # Check that cert is subordinate to cert_next
        pk = cert_next.public_key()
        pk.verify(cert.signature, cert.tbs_certificate_bytes,
                  ec.ECDSA(cert.signature_hash_algorithm))

        valid.append(cert)
        cert = cert_next

    valid.append(cert)

    # Check that remaining cert is equal to root
    if root.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
        raise Exception('Root certificate fingerprint does not match chain root, aborting')



if __name__ == '__main__':
    # Test Apple certificate chain
    cert_chain_raw_good = [ bytearray.fromhex('30820243308201c9a003020102020601779e45a1bd300a06082a8648ce3d0403023048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3231303231333032303133395a170d3231303231363032303133395a3081913149304706035504030c4030326631346235316537383963333366666561643561316139303738653334633162666634626634313064313238386338626365356530373034306431316536311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d03010703420004ef53b98262ba5ae96cbcb5fc73a529e207c968f771c29b60cc786144ed78c0e54c9396c99ca097331090f2ceb421d736781e155f744c599d91e7dea21feb92cba3553053300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f0303306092a864886f76364080204263024a12204202172935a7c1adf60c84e804769285222be2d5e357efcfd7df6cfa2cac35db06a300a06082a8648ce3d040302036800306502310086cfd661a7731ef2cc37ef9337ed9990e652f9d4333e4ab612565fef9e416ddd2810ed5feff5179a521d4f4336ff67db023019988f1c649298c41c5c86b6217dac70a4b208d749973c77cdc5243762b48def531c828ccb40d64ec3bf19b31a3db3de'), bytearray.fromhex('30820234308201baa003020102021056255395c7a7fb40ebe228d8260853b6300a06082a8648ce3d040303304b311f301d06035504030c164170706c6520576562417574686e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333830315a170d3330303331333030303030305a3048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b8104002203620004832e872f261491810225b9f5fcd6bb6378b5f55f3fcb045bc735993475fd549044df9bfe19211765c69a1dda050b38d45083401a434fb24d112d56c3e1cfbfcb9891fec0696081bef96cbc77c88dddaf46a5aee1dd515b5afaab93be9c0b2691a366306430120603551d130101ff040830060101ff020100301f0603551d2304183016801426d764d9c578c25a67d1a7de6b12d01b63f1c6d7301d0603551d0e04160414ebae82c4ffa1ac5b51d4cf24610500be63bd7788300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030368003065023100dd8b1a3481a5fad9dbb4e7657b841e144c27b75b876a4186c2b1475750337227efe554457ef648950c632e5c483e70c102302c8a6044dc201fcfe59bc34d2930c1487851d960ed6a75f1eb4acabe38cd25b897d0c805bef0c7f78b07a571c6e80e07') ]

    # Broken chain
    cert_chain_raw_bad = [ bytearray.fromhex('30820243308201c9a003020102020601779e45a1bd300a06082a8648ce3d0403023048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3231303231333032303133395a170d3231303231363032303133395a3081913149304706035504030c4030326631346235316537383963333366666561643561316139303738653334633162666634626634313064313238386338626365356530373034306431316536311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d03010703420004ef53b98262ba5ae96cbcb5fc73a529e207c968f771c29b60cc786144ed78c0e54c9396c99ca097331090f2ceb421d736781e155f744c599d91e7dea21feb92cba3553053300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f0303306092a864886f76364080204263024a12204202172935a7c1adf60c84e804769285222be2d5e357efcfd7df6cfa2cac35db06a300a06082a8648ce3d040302036800306502310086cfd661a7731ef2cc37ef9337ed9990e652f9d4333e4ab612565fef9e416ddd2810ed5feff5179a521d4f4336ff67db023019988f1c649298c41c5c86b6217dac70a4b208d749973c77cdc5243762b48def531c828ccb40d64ec3bf19b31a3db3de'), bytearray.fromhex('30820243308201c9a003020102020601779e45a1bd300a06082a8648ce3d0403023048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3231303231333032303133395a170d3231303231363032303133395a3081913149304706035504030c4030326631346235316537383963333366666561643561316139303738653334633162666634626634313064313238386338626365356530373034306431316536311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d03010703420004ef53b98262ba5ae96cbcb5fc73a529e207c968f771c29b60cc786144ed78c0e54c9396c99ca097331090f2ceb421d736781e155f744c599d91e7dea21feb92cba3553053300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f0303306092a864886f76364080204263024a12204202172935a7c1adf60c84e804769285222be2d5e357efcfd7df6cfa2cac35db06a300a06082a8648ce3d040302036800306502310086cfd661a7731ef2cc37ef9337ed9990e652f9d4333e4ab612565fef9e416ddd2810ed5feff5179a521d4f4336ff67db023019988f1c649298c41c5c86b6217dac70a4b208d749973c77cdc5243762b48def531c828ccb40d64ec3bf19b31a3db3de'), bytearray.fromhex('30820234308201baa003020102021056255395c7a7fb40ebe228d8260853b6300a06082a8648ce3d040303304b311f301d06035504030c164170706c6520576562417574686e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333830315a170d3330303331333030303030305a3048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b8104002203620004832e872f261491810225b9f5fcd6bb6378b5f55f3fcb045bc735993475fd549044df9bfe19211765c69a1dda050b38d45083401a434fb24d112d56c3e1cfbfcb9891fec0696081bef96cbc77c88dddaf46a5aee1dd515b5afaab93be9c0b2691a366306430120603551d130101ff040830060101ff020100301f0603551d2304183016801426d764d9c578c25a67d1a7de6b12d01b63f1c6d7301d0603551d0e04160414ebae82c4ffa1ac5b51d4cf24610500be63bd7788300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030368003065023100dd8b1a3481a5fad9dbb4e7657b841e144c27b75b876a4186c2b1475750337227efe554457ef648950c632e5c483e70c102302c8a6044dc201fcfe59bc34d2930c1487851d960ed6a75f1eb4acabe38cd25b897d0c805bef0c7f78b07a571c6e80e07') ]

    try:
        cert_chain_good = [x509.load_der_x509_certificate(cert, default_backend()) for cert in cert_chain_raw_good]
        check_cert_chain(cert_chain_good, cert_chain_good[1])
    except Exception as e:
        print('No exception was expected, aborting. Got: {}'.format(e))
        raise

    try:
        cert_chain_bad = [x509.load_der_x509_certificate(cert, default_backend()) for cert in cert_chain_raw_bad]
        check_cert_chain(cert_chain_bad, cert_chain_bad[1])
    except Exception as e:
        print('Got expected exception: {}'.format(e))

