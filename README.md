# eckey-testing
Linux elliptic curve key testing (expected support of EC keys in Linux 5.12)

This project currently hosts some simple tests scripts for Linux elliptic curve key support testing. Some of the scripts may need to be adapted for testing with other curves than prime256v1.

- create_linux_tvs.sh: Create Linux kernel test vectors for usage with crypto/testmgr.h; some post-editing of the output is required
- generates.sh + load-keys-kernel.sh: generate CAs and certified keys and then load them into the kernel using restricted keyrings
- test-ecc-kernel-keys.sh: Endless test for loading a certified elliptic curve key into the kernel; sometimes an error is injected into the certificate resulting in an expected rejection of the key
