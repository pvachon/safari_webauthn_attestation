# Quick Experiment in WebAuthn on Safari
This is a quick hacked up set of scripts for experimenting with Webauthn on
Safari. This is intended to show how to perform chunks of attestation, but
does not yet check certificate chaining (an exercise for the reader ATM).

The test harness is built on top of Flask, uses jQuery, but is otherwise
very minimal. You can just install the Python requirements in a virtualenv
and you should be off to the races:

```
# Clone this repo somewhere, navigate to where you cloned it, then...
virtualenv -ppython3 ve
ve/bin/pip install -r requirements.txt
FLASK_APP=wa_server.py ve/bin/python3 -m flask run --host=0.0.0.0
```

This binds to all interfaces, drop the `--host=0.0.0.0` if you're in an
environment where this is risky behaviour.

Navigate to wherever you're running this (i.e. http://localhost:5000) and
click the magic button to generate an identity. That's all there is to it.

This code is a demo - there are many best practices that it does not follow
and is far from a complete application. Use it for inspiration at most, but
be in awe of its flaws as well.

## What is done
 * Extracting various fields from the user data and attestation data
 * Generating the nonce and extracting it from the end entity cert
 * Ensuring the end-entity cert public key matches auth data

## What needs to be done
 * Checking the cert chain is rooted in the pinned AAA root

