This is the fork of [soft-webauthn](https://github.com/bodik/soft-webauthn) library to make it more usable in security testing. Some functionality was and will be altered thus any assumptions in interchangeability with the original library may be wrong.

**Never use it in production.**

Improvements:

- Can store multiple keys. Implementation nearly stateless (stores only master key and global counter).
- Can be pickled / unpickled.
- Can be initialized with constant key.
- Can easily extract private_key from `credential_id` (sometimes also referred as `key_id`).

Limitations:

- Supports only ES256 algorithm (aka `{'alg': -7}`).
- Attestation is not supported.
- Resident Keys are not supported.
- Yeah, even timeouts are not supported.
- Validation is poor and definetely not compliant with [W3C Recommendation](https://www.w3.org/TR/webauthn/).

