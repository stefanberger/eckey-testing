#!/usr/bin/env bash

# shellcheck disable=SC2059

# Test loading of self-signed x509 certificates holding elliptic curve keys.
# A list of curves and hashes to test with can be passed as shown below.
# Only curves supported by openssl and the kernel will be tried. To
# check which ones are supported by openssl run 'openssl ecparam -list_curves'.
#
# By default the following curves will be tested:
# - prime192v1
# - prime256v1
# - secp384r1
# - secp521r
#
# On hashes supported by openssl and the kernel will be tried. To
# check which ones are supported by openssl run 'openssl dgst -list'
#
# By default the following hashes will be tested:
# - sha224
# - sha256
# - sha384
# - sha512
# - sha3-256
# - sha3-384
# - sha3-512
#
# HASHES="sha256 sha3-256" CURVES="prime256v1" ./test-ecc-kernel-keys.sh

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

get_testable_curves() {
  local curves=$1

  local curve tmp tmpcurves

  for curve in ${curves}; do
    tmp=$(openssl ecparam -list_curves | grep -E "\s*${curve}\s*:")
    if [ -n "${tmp}" ]; then
      tmpcurves="${tmpcurves} ${curve}"
    fi
  done

  curves=${tmpcurves}
  tmpcurves=""
  for curve in ${curves}; do
    case "${curve}" in
    prime192v1) tmp="ecdsa-nist-p192";;
    prime256v1) tmp="ecdsa-nist-p256";;
    secp384r1) tmp="ecdsa-nist-p384";;
    secp521r1) tmp="ecdsa-nist-p521";;
    *) echo "Internal error: Unknown curve $curve" >&2; exit 1;;
    esac
    if grep -q "${tmp}" /proc/crypto; then
      tmpcurves="${tmpcurves} ${curve}"
    else
      echo "${curve} not supported by kernel driver" >&2
    fi
  done

  echo "${tmpcurves}"
}

get_testable_hashes() {
  local hashes=$1

  local hash tmp tmphashes

  for hash in ${hashes}; do
    if echo | openssl dgst "-${hash}" &>/dev/null; then
      tmphashes="${tmphashes} ${hash}"
    fi
  done

  hashes=${tmphashes}
  tmphashes=""
  for hash in ${hashes}; do
    case "${hash}" in
    sha1|sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512)
      tmp="${hash}-generic";;
    *) echo "Internal error: Unknown hash ${hash}" >&2; exit 1;;
    esac
    if grep -q "${tmp}" /proc/crypto; then
      tmphashes="${tmphashes} ${hash}"
    else
      echo "${hash} not supported by kernel driver" >&2
    fi
  done

  echo "${tmphashes}"
}

main() {
  local certfile id curves rc hashes

  keyctl newring test @u 1>/dev/null

  if ! grep -q -E ": ecdsa-nist-p(192|256|384|521)" /proc/crypto; then
    echo "Kernel does not support any NIST curves. Try 'sudo modprobe ecdsa_generic'." >&2
    exit 1
  fi

  curves=${CURVES:-prime256v1 prime192v1 secp384r1 secp521r1}
  curves=$(get_testable_curves "${curves}")
  if [ -z "${curves}" ]; then
    echo "No curves to test with. Try one of the following:"
    openssl ecparam -list_curves
    exit 1
  fi
  echo "Testing with curves: ${curves}"

  # exclude: sha1 (old), sha3-224 (not working with some curves)
  hashes=${HASHES:-sha224 sha256 sha384 sha512 sha3-256 sha3-384 sha3-512}
  hashes=$(get_testable_hashes "${hashes}")
  if [ -z "${hashes}" ]; then
    echo "No hashes to test with. Try one of the following:"
    openssl dgst -list
    exit 1
  fi
  echo "Testing with hashes: ${hashes}"

  while :; do
    for curve in ${curves}; do
      for hash in ${hashes}; do
        certfile="cert.der"
        openssl req \
                -x509 \
                "-${hash}" \
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
          0) printf "Good: curve: %10s hash: %8s keyid: %-10s" "$curve" "$hash" "$id";;
          *) printf "Good: curve: %10s hash: %8s keyid: %-10s -- bad certificate was rejected\n" "$curve" "$hash" "$id";;
          esac
        fi
        if [ -n "${id}" ]; then
          local sigsz off byte1 byte2

          echo "test" >> raw-in
          openssl dgst "-${hash}" -binary raw-in > raw-in.hash
          openssl pkeyutl -sign -inkey key.pem -in raw-in.hash -out sig.bin
          if ! keyctl pkey_verify "${id}" 0 raw-in.hash sig.bin "hash=${hash}" enc=x962; then
            printf "\n\nSignature verification failed"
            exit 1
          fi
          sigsz=$(stat -c%s sig.bin)

          # Try verification with bad signatures
          for _ in $(seq 0 19); do
            cp sig.bin sig.bin.bad

            off=$((RANDOM % (sigsz-1)))
            # Generate a bad signature by injecting 2 random bytes into the file at some offset
            byte1=$(printf "%02x" $((RANDOM % 255)))
            byte2=$(printf "%02x" $((RANDOM % 255)))
            printf "\x${byte1}\x${byte2}" |
              dd of=sig.bin.bad bs=1 count=2 seek=$((off)) conv=notrunc status=none
            if keyctl pkey_verify "${id}" 0 raw-in.hash sig.bin.bad "hash=${hash}" enc=x962 &>/dev/null; then
              # Accidentally verified - Must also pass with openssl
              if ! openssl pkeyutl \
                     -verify \
                     -in raw-in.hash \
                     -sigfile sig.bin.bad \
                     -pkeyopt "digest:${hash}" \
                     -inkey key.pem &>/dev/null; then
                printf "\n\nBAD: Kernel driver reported successful verification of bad signature"
                exit 1
              fi
            fi
          done
          printf " Signature test passed\n"

          # check for fixes introduced by
          # https://lore.kernel.org/linux-crypto/cover.1735236227.git.lukas@wunner.de/T/#mf161d128e8f7a8498c64e66d69dd666a1385c382
          if ! keyctl pkey_query "${id}" 0 enc=x962 "hash=${hash}" > pkey_query.out; then
            printf "\nWarning: pkey_query failed on key\n"
          else
            keylen=$(sed -n 's/key_size=//p' pkey_query.out)
            # keylen is part of the curve name
            if ! [[ "${curve}" =~ ${keylen} ]]; then
              printf "\nWarning: Wrong key length indicated by pkey_query on ${curve} for key ${id}: ${keylen}\n"
            fi
          fi

        fi
      done
    done
  done
}

main
