"""SoftWebauthnDevice class tests"""

import copy

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap2 import AttestedCredentialData
from fido2.utils import sha256
from base64 import urlsafe_b64encode

from webauthn_software_authenticator import SoftWebauthnDevice


# PublicKeyCredentialCreationOptions
PKCCO = {
    'publicKey': {
        'rp': {
            'name': 'example org',
            'id': 'example.org'
        },
        'user': {
            'id': b'randomhandle',
            'name': 'username',
            'displayName': 'user name'
        },
        'challenge': b'arandomchallenge',
        'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
        'attestation': 'none'
    }
}

# PublicKeyCredentialRequestOptions
PKCRO = {
    'publicKey': {
        'challenge': b'arandomchallenge',
        'rpId': 'example.org',
    }
}


def test_as_attested_cred():
    """test straight credential generation and access"""

    device = SoftWebauthnDevice()
    credential_id, private_key = device.cred_init('rpid')

    assert isinstance(device.cred_as_attested(credential_id, private_key), AttestedCredentialData)


def test_create():
    """test create"""

    device = SoftWebauthnDevice()
    attestation = device.create(PKCCO, 'https://example.org')

    assert attestation
    assert attestation['response']['attestationObject']
    assert attestation['id']
    assert attestation['rawId']
    assert urlsafe_b64encode(attestation['rawId']).decode() == attestation['id']


def test_create_not_supported_type():
    """test for internal class check"""

    device = SoftWebauthnDevice()
    pkcco = copy.deepcopy(PKCCO)
    pkcco['publicKey']['pubKeyCredParams'][0]['alg'] = -8

    with pytest.raises(ValueError):
        device.create(pkcco, 'https://example.org')


def test_create_not_supported_attestation():
    """test for internal class check"""

    device = SoftWebauthnDevice()
    pkcco = copy.deepcopy(PKCCO)
    pkcco['publicKey']['attestation'] = 'direct'

    with pytest.raises(ValueError):
        device.create(pkcco, 'https://example.org')


def test_get():
    """test get"""

    device = SoftWebauthnDevice()
    credential_id, private_key = device.cred_init(PKCRO['publicKey']['rpId'])

    pkcro = copy.deepcopy(PKCRO)
    pkcro['publicKey']['allowCredentials'] = [
        {
            "type": "public-key",
            "id": credential_id
        }
    ]

    assertion = device.get(pkcro, 'https://example.org')

    assert assertion
    private_key.public_key().verify(
        assertion['response']['signature'],
        assertion['response']['authenticatorData'] + sha256(assertion['response']['clientDataJSON']),
        ec.ECDSA(hashes.SHA256())
    )


def test_get_not_matching_rpid():
    """test get not mathcing rpid"""

    device = SoftWebauthnDevice()
    credential_id, private_key = device.cred_init('rpid')

    pkcro = copy.deepcopy(PKCRO)
    pkcro['publicKey']['rpId'] = 'another_rpid'
    pkcro['publicKey']['allowCredentials'] = [
        {
            "type": "public-key",
            "id": credential_id
        }
    ]
    with pytest.raises(ValueError):
        device.get(pkcro, 'https://example.org')
