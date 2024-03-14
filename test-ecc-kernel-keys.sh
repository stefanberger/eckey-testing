#!/usr/bin/env bash

# Test loading of self-signed x509 certificates holding elliptic curve keys.
# A list of curves to test can be passed as shown below. If a key fails to
# load because the curve is not supported by the kernel, the script will end.
# Only the curves supported by openssl will be tried. To check which ones
# are supported run 'openssl ecparam -list_curves'.
# By default the following curves will be tested: prime192v1 prime256v1
#
# CURVES="prime256v1" ./test-ecc-kernel-keys.sh

# Inject a fault into the certificate's key
inject_fault_cert_key() {
  local certfilein="$1"
  local certfileout="$2"

  local line offset hl skip

  cp -f "${certfilein}" "${certfileout}"

  line=$(openssl asn1parse -inform der -in "${certfilein}" |
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

# Inject a fault into the certificate's signature
inject_fault_cert_signature() {
  local certfilein="$1"
  local certfileout="$2"

  local line offset hl skip

  cp -f "${certfilein}" "${certfileout}"

  line=$(openssl asn1parse -inform der -in "${certfilein}" |
        grep "BIT STRING" |
        tail -n1)
  offset=$(echo "${line}" | cut -d":" -f1)

  # At the offset it looks like this from prime256v1: 03 47 00 30 44 02 20 14
  # We want to get to the '14'; skip over 5 bytes of header
  hl=5
  # go a bit 'into' the key parameters to '14'
  skip=2
  # inject 3 bytes of bad key data -- it's unlikely this is valid data
  #dd if=${certfile} bs=1 count=3 skip=$((offset+hl+skip)) status=none | od -tx1
  #sha1sum $certfile
  # inject 3 bytes of bad key data -- it's unlikely this is the same as the original
  printf '\x01\x23\x45' | \
    dd of="${certfileout}" bs=1 count=3 seek=$((offset+hl+skip)) conv=notrunc status=none
  #dd if=${certfile} bs=1 count=3 skip=$((offset+hl+skip)) status=none | od -tx1
  #sha1sum $certfile
}

main() {
  local certfile id tmp curves tmpcurves rc

  keyctl newring test @u

  curves=${CURVES:-prime256v1 prime192v1 secp384r1}
  for curve in ${curves}; do
    tmp=$(openssl ecparam -list_curves | grep -E "\s*${curve}\s*:")
    if [ -n "${tmp}" ]; then
      tmpcurves="${tmpcurves} ${curve}"
    fi
  done
  curves=${tmpcurves}
  if [ -z "${curves}" ]; then
    echo "No curves to test with. Try one of the following:"
    openssl ecparam -list_curves
    exit 1
  fi
  echo "Testing with curves: ${curves}"

  while :; do
    for curve in ${curves}; do
      for hash in sha1 sha224 sha256 sha384 sha512; do
        certfile="cert.der"
        openssl req \
                -x509 \
                -${hash} \
                -newkey ec \
                -pkeyopt "ec_paramgen_curve:${curve}" \
                -keyout key.pem \
                -days 365 \
                -subj '/CN=test' \
                -nodes \
                -outform der \
                -out "${certfile}" 2>/dev/null

        exp=0
        # Every once in a while we inject a fault into the
        # certificate's key or signature
        case $((RANDOM & 255)) in
        255)
          inject_fault_cert_key "${certfile}" "${certfile}.bad"
          certfile="${certfile}.bad"
          exp=1
        ;;
        254)
          inject_fault_cert_signature "${certfile}" "${certfile}.bad"
          certfile="${certfile}.bad"
          exp=1
        ;;
        esac

        id=$(keyctl padd asymmetric testkey %keyring:test < "${certfile}")
        rc=$?
        if [ $rc -ne $exp ]; then
          case "$exp" in
          0) echo "Error: Could not load valid certificate!";;
          1) echo "Error: Succeeded to load invalid certificate!";;
          esac
          echo "curve: $curve hash: $hash"
          exit 1
        else
          case "$rc" in
          0) printf "Good: curve: %10s hash: %-7s keyid: %-10s\n" "$curve" $hash "$id";;
          *) printf "Good: curve: %10s hash: %-7s keyid: %-10s -- bad certificate was rejected\n" "$curve" $hash "$id";;
          esac
        fi
      done
    done
  done
}

main
