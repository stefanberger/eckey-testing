#!/usr/bin/env bash

create_rsa_ca() {
	dir="$1"
	echo "Creating RSA CA"
	mkdir ${dir}
	mkdir -p ${dir}/ca.db.certs
	touch ${dir}/ca.db.index
	echo "01" > ${dir}/ca.db.serial

	openssl req -x509 \
		-newkey rsa:2048 -keyout ${dir}/ca.key -nodes \
		-days 3650 -out ${dir}/ca.crt \
		-subj '/CN=Testing-RSA-CA'

	openssl x509 -in ${dir}/ca.crt \
		-outform der -out ${dir}/ca.crt.der

	cat <<_EOF_ > ${dir}/rsaca.conf
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./${dir}
certs = \$dir
new_certs_dir = \$dir/ca.db.certs
database = \$dir/ca.db.index
serial = \$dir/ca.db.serial
RANDFILE = \$dir/ca.db.rand
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_days = 365
default_crl_days = 30
default_md = sha384
preserve = no
policy = generic_policy

x509_extensions = usr_cert

[ usr_cert ]

basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions        = v3_req
distinguished_name     = dn

[dn]

[v3_req]

#subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:false

[v3_ca]

subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true

_EOF_
}

create_ecdsa_ca() {
	dir="$1"
	echo "Creating ECDSA CA"
	mkdir -p ${dir}/ca.db.certs
	touch ${dir}/ca.db.index
	echo "01" > ${dir}/ca.db.serial

	openssl req -x509 \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout ${dir}/ca.key -nodes \
		-days 3650 -out ${dir}/ca.crt \
		-subj '/CN=Testing-ECDSA-CA'

	openssl x509 -in ${dir}/ca.crt \
		-outform der -out ${dir}/ca.crt.der

	cat <<_EOF_ > ${dir}/ecdsaca.conf
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./${dir}
certs = \$dir
new_certs_dir = \$dir/ca.db.certs
database = \$dir/ca.db.index
serial = \$dir/ca.db.serial
RANDFILE = \$dir/ca.db.rand
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_days = 365
default_crl_days = 30
default_md = sha1
preserve = no
policy = generic_policy

x509_extensions = usr_cert

[ usr_cert ]

basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions        = v3_req
distinguished_name     = dn

[dn]

[v3_req]

#subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:false

[v3_ca]

subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true

_EOF_
}


dir=rsa-ca
if [ ! -d $dir ]; then
	create_rsa_ca "${dir}"
fi

dir=ecdsa-ca
if [ ! -d $dir ]; then
	create_ecdsa_ca "${dir}"
fi

if [ ! -f eckey.pem ]; then
	echo "Creating EC key"
	openssl ecparam -name prime256v1 -genkey -noout -out eckey.pem
	openssl ec -in eckey.pem -pubout -out eckeypub.pem
fi

if [ ! -f eckey-ecdsa.crt.der ]; then
	echo "Using ECDSA CA to sign EC key"
	openssl req -new -config ecdsa-ca/ecdsaca.conf \
		-key eckey.pem -out myreq-eckey.pem \
		-subj '/CN=ecdsa-ca-signed-ec-key' \
		-reqexts v3_req
	openssl ca -config ecdsa-ca/ecdsaca.conf \
		-out eckey-ecdsa.pem -infiles myreq-eckey.pem
	openssl x509 -in eckey-ecdsa.pem -outform der -out eckey-ecdsa.crt.der
	openssl verify -verbose -CAfile ecdsa-ca/ca.crt eckey-ecdsa.pem
fi

if [ ! -f eckey-rsa.crt.der ]; then
	echo "Using RSA CA to sign EC key"
	openssl req -new -config rsa-ca/rsaca.conf \
		-key eckey.pem -out myreq-rsakey.pem \
		-subj '/CN=rsa-ca-signed-ec-key' \
		-reqexts v3_req
	openssl ca -config rsa-ca/rsaca.conf \
		-out eckey-rsa.pem -infiles myreq-rsakey.pem
	openssl x509 -in eckey-rsa.pem -outform der -out eckey-rsa.crt.der
	openssl verify -verbose -CAfile rsa-ca/ca.crt eckey-rsa.pem
fi
