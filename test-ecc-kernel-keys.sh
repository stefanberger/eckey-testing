#!/usr/bin/env bash

keyctrl newring test @u

while :; do
	for hash in sha1 sha224 sha256 sha384 sha512; do
		openssl req \
			-x509 \
			-${hash} \
			-newkey ec \
			-pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout key.pem \
			-days 365 \
			-subj '/CN=test' \
			-nodes \
			-outform der \
			-out cert.der
		keyctl padd asymmetric testkey %keyring:test < cert.der
		if [ $? -ne 0 ]; then
			echo "ERROR"
			exit 1
		fi
	done
done

	
