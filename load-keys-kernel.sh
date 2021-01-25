#!/usr/bin/env bash

# Create and populate a keyring for root certificates
root_id=`keyctl add keyring root-certs "" @s`
keyctl padd asymmetric "" $root_id < ecdsa-ca/ca.crt.der
keyctl padd asymmetric "" $root_id < rsa-ca/ca.crt.der

# Create and restrict a keyring for the certificate chain
chain_id=`keyctl add keyring chain "" @s`
keyctl restrict_keyring $chain_id asymmetric key_or_keyring:$root_id:chain

keyctl padd asymmetric "" $chain_id < eckey-ecdsa.crt.der
keyctl padd asymmetric "" $chain_id < eckey-rsa.crt.der
	