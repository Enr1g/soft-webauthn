import setuptools

setuptools.setup(
    name='webauthn-software-authenticator',
    description='Python Software Authenticator for WebAuthn',
    url='https://github.com/Enr1g/webauthn-software-authenticator',
    py_modules=['webauthn_software_authenticator'],
    install_requires=[
        'fido2>=0.8',
        'cryptography'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
