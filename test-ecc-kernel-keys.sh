#!/usr/bin/env bash

# Inject a fault into the certificate's key
inject_fault_cert() {
  local certfilein="$1"
  local certfileout="$2"

  local line offset

  cp -f "${certfilein}" "${certfileout}"

  line=$(openssl asn1parse -inform der -in ${certfilein} |
        grep "BIT STRING" |
        head -n1)
  offset=$(echo "${line}" | cut -d":" -f1)

  # header length always assumed to be '2'
  hl=2
  # go a bit 'into' the key parameters
  skip=4
  # inject 3 bytes of bad key data -- it's unlikely this is valid data
  #dd if=${certfile} bs=1 count=3 skip=$((offset+hl+skip)) status=none | od -tx1
  #sha1sum $certfile
  # inject 3 bytes of bad key data -- it's unlikely this is the same as the original
  printf '\x00\x00\x00' | \
    dd of="${certfileout}" bs=1 count=3 seek=$((offset+hl+skip)) conv=notrunc status=none
  #dd if=${certfile} bs=1 count=3 skip=$((offset+hl+skip)) status=none | od -tx1
  #sha1sum $certfile
}

main() {
  local certfile id

  keyctl newring test @u

  curves="prime256v1"

  while :; do
    for curve in $(echo ${curves}); do
      for hash in sha1 sha224 sha256 sha384 sha512; do
         certfile="cert.der"
         openssl req \
                -x509 \
		-${hash} \
		-newkey ec \
		-pkeyopt ec_paramgen_curve:${curve} \
		-keyout key.pem \
		-days 365 \
		-subj '/CN=test' \
		-nodes \
		-outform der \
		-out ${certfile} 2>/dev/null


		exp=0
		# Every once in a while we inject a fault into the
		# certificate's key
		if [ $((RANDOM & 255)) -eq 255 ]; then
			inject_fault_cert "${certfile}" "${certfile}.bad"
			certfile="${certfile}.bad"
			exp=1
		fi
		id=$(keyctl padd asymmetric testkey %keyring:test < "${certfile}")
		if [ $? -ne $exp ]; then
			case "$exp" in
			0) echo "Error: Could not load valid certificate!";;
			1) echo "Error: Succeeded to load invalid certificate!";;
			esac
			echo "curve: $curve hash: $hash"
			exit 1
		else
			printf "Good: curve: %10s hash: %-7s keyid: %-10s\n" $curve $hash $id
		fi
      done
    done
  done
}

main
