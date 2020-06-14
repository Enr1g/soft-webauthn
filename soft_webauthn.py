"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import json
from base64 import urlsafe_b64encode
from struct import pack
from typing import Any, Dict, Optional

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import AttestedCredentialData
from fido2.utils import sha256


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """
    aaguid: bytes = b'\x00'*16

    def __init__(self, master_key: bytes = None, sign_count: int = 0):
        if master_key is None:
            self.master_key: bytes = AESGCM.generate_key(bit_length=128)
        else:
            self.master_key = master_key

        self.sign_count: int = sign_count

    def cred_init(self, rp_id: str) -> (bytes, ec.EllipticCurvePrivateKey):
        """initialize credential_id for rp_id and private_key"""

        rp_id_hash = sha256(rp_id.encode())
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # This may look like a cryptography but it's not.
        # Never try to use it in a real project.
        aesgcm = AESGCM(self.master_key)
        data = private_key.private_numbers().private_value.to_bytes(32, 'big')
        aad = rp_id_hash
        nonce = sha256(aad + self.master_key)[4:16]
        credential_id = aesgcm.encrypt(nonce, data, aad)

        return credential_id, private_key

    def cred_extract(self, rp_id: str, credential_id: bytes) -> Optional[ec.EllipticCurvePrivateKey]:
        rp_id_hash = sha256(rp_id.encode())

        aesgcm = AESGCM(self.master_key)
        aad = rp_id_hash
        nonce = sha256(aad + self.master_key)[4:16]

        try:
            data = aesgcm.decrypt(nonce, credential_id, aad)
            return ec.derive_private_key(int.from_bytes(data, 'big'), ec.SECP256R1(), default_backend())
        except cryptography.exceptions.InvalidTag:
            return None

    def cred_as_attested(self, credential_id: bytes, private_key: ec.EllipticCurvePrivateKey) -> AttestedCredentialData:
        """return current credential as AttestedCredentialData"""

        return AttestedCredentialData.create(
            self.aaguid,
            credential_id,
            ES256.from_cryptography_key(private_key.public_key())
        )

    def create(self, options: Dict[str, Any], origin: str) -> Dict[str, Any]:
        """create credential and return PublicKeyCredential object aka attestation"""

        if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        if ('attestation' in options['publicKey']) and (options['publicKey']['attestation'] != 'none'):
            raise ValueError('Only none attestation supported')

        rp_id = options['publicKey']['rp']['id']
        # user_id = options['publicKey']['user']['id']

        # prepare new key
        credential_id, private_key = self.cred_init(rp_id)

        # generate credential response
        client_data = {
            'type': 'webauthn.create',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }

        rp_id_hash = sha256(rp_id.encode())
        flags = b'\x41'  # attested_data + user_present
        sign_count = pack('>I', self.sign_count)
        credential_id_length = pack('>H', len(credential_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(private_key.public_key()))
        attestation_object = {
            'authData':
                rp_id_hash + flags + sign_count
                + self.aaguid + credential_id_length + credential_id + cose_key,
            'fmt': 'none',
            'attStmt': {}
        }

        return {
            'id': urlsafe_b64encode(credential_id),
            'rawId': credential_id,
            'response': {
                'clientDataJSON': json.dumps(client_data).encode('utf-8'),
                'attestationObject': cbor.encode(attestation_object)
            },
            'type': 'public-key'
        }

    def get(self, options: Dict[str, Any], origin: str) -> Dict[str, Any]:
        """get authentication credential aka assertion"""

        rp_id = options['publicKey']['rpId']

        for creds in options['publicKey']['allowCredentials']:
            credential_id = creds['id']

            private_key = self.cred_extract(rp_id, credential_id)

            if private_key is None:
                continue

            self.sign_count += 1

            # prepare signature
            client_data = json.dumps({
                'type': 'webauthn.get',
                'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
                'origin': origin
            }).encode('utf-8')
            client_data_hash = sha256(client_data)

            rp_id_hash = sha256(rp_id.encode())
            flags = b'\x01'
            sign_count = pack('>I', self.sign_count)
            authenticator_data = rp_id_hash + flags + sign_count

            signature = private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

            # generate assertion
            return {
                'id': urlsafe_b64encode(credential_id),
                'rawId': credential_id,
                'response': {
                    'authenticatorData': authenticator_data,
                    'clientDataJSON': client_data,
                    'signature': signature,
                    'userHandle': None
                },
                'type': 'public-key'
            }

        raise ValueError("No matching key was found")
