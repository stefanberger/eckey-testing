#!/usr/bin/env bash

# Script to generate Linux test vectors

CURVE="prime256v1"

for hash in sha1 sha224 sha256 sha384 sha512; do
	openssl req \
		-x509 \
		-${hash} \
		-newkey ec \
		-pkeyopt ec_paramgen_curve:${CURVE} \
		-keyout key.pem \
		-days 365 \
		-subj '/CN=test' \
		-nodes \
		-outform der \
		-out cert.der

	# key
	line=$(openssl asn1parse -in cert.der -inform der |
		grep "BIT STRING" | head -n1)
	#echo $line
	skip=$(echo $line | cut -d":" -f1)
	#echo $skip
	length=$(echo $line | sed -n 's/.*l=\s*\([^ ]*\).*/\1/p')
	#echo "l=$length"
	echo -e "\t.key ="
	dd bs=1 count=$((length-1)) skip=$((skip+3)) if=cert.der 2>/dev/null |
		od -tx1 |
		sed -n "s/^[0-9]\{7\} \(.*\)$/\t\" \1/p" |
		sed -n "s/ \([0-9a-f]\)/\\\x\1/gp"
	echo ","
	echo -e "\t.key_len = ,"
	#openssl asn1parse -in cert.der -inform der
	line=$(openssl asn1parse -in cert.der -inform der 2>&1|
		grep id-ecPublicKey -B1 |
		head -n1)
	#echo $line
	skip=$(echo $line | cut -d":" -f1)
	#echo $skip
	length=$(echo $line | sed -n 's/.*l=\s*\([^ ]*\).*/\1/p')
	#echo "l=$length"
	echo -e "\t.params ="
	dd bs=1 count=$((length+2)) skip=$skip if=cert.der 2>/dev/null |
		od -tx1 |
		sed -n "s/^[0-9]\{7\} \(.*\)$/\t\" \1/p" |
		sed -n "s/ \([0-9a-f]\)/\\\x\1/gp"
	echo ","
	echo -e "\t.param_len = $((length + 2)),"

	message="${RANDOM}${RANDOM}"
	echo -e "\t.m ="
	echo -en "${message}" |
		openssl dgst \
		-${hash} | \
		sed -n "s/.*= \(.*\)$/\t\"\1/p" | \
		sed -n "s/[0-9a-f]\{2\}/\\\x\0/pg"
	echo ","
	echo -e "\t.m_size = ,"
	echo -e "\t.algo = OID_id_ecdsa_with_${hash},"
	# get the signature
	echo -e "\t.c ="
	echo -en "${message}" |
		openssl dgst \
		-${hash} \
		-sign key.pem |
		od -tx1 |
		sed -n "s/^[0-9]\{7\} \(.*\)$/\t\" \1/p" |
		sed -n "s/ \([0-9a-f]\)/\\\x\1/gp"
	echo ","
	echo -e "\t.c_size = ,"
	echo -e "\t.public_key_vec = true,"
	echo -e "\t.siggen_sigver_test = true,"
done
