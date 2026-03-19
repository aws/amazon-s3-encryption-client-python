# Compliance Exceptions for Encryption Implementation

## Summary

The Python S3 Encryption Client does not implement AES-CTR algorithm suites (used only for ranged-get decryption),
does not yet validate IV/Message ID for zero values, does not validate maximum plaintext length,
and relies on Python's `cryptography` library to automatically append GCM auth tags.

## AES-CTR Algorithm Suites

##= specification/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
##= type=exception
##% Attempts to encrypt using key committing AES-CTR MUST fail.

Justification: The AES-CTR algorithm suites are only used for ranged-get decryption. Since ranged gets are not yet implemented, these algorithm suites are not defined in the `AlgorithmSuite` enum and cannot be selected for encryption. The constraint is satisfied structurally.

---

##= specification/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
##= type=exception
##% Attempts to encrypt using AES-CTR MUST fail.

Justification: Same as above. AES-CTR is not available as an algorithm suite option, so it cannot be used for encryption.

---

## GCM Auth Tag Appending

##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
##= type=exception
##% The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.

Justification: Python's `cryptography` library (`AESGCM.encrypt`) automatically appends the GCM authentication tag to the ciphertext. No manual appending is needed.

---

##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
##= type=exception
##% The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.

Justification: Python's `cryptography` library (`AESGCM.encrypt`) automatically appends the GCM authentication tag to the ciphertext. No manual appending is needed.

---

## Cipher Initialization Validation

##= specification/s3-encryption/encryption.md#cipher-initialization
##= type=exception
##% The client SHOULD validate that the generated IV or Message ID is not zeros.

Justification: This SHOULD-level validation is not yet implemented. The IV and Message ID are generated using `os.urandom()`, which is cryptographically secure and extremely unlikely to produce all-zero output. This validation is planned for a future release.

---

## Plaintext Length Validation

##= specification/s3-encryption/encryption.md#content-encryption
##= type=exception
##% The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.

Justification: Maximum plaintext length validation is not yet implemented. For AES-GCM with a 12-byte IV, the maximum plaintext size is approximately 64 GiB, which exceeds practical S3 single-object upload limits. This validation is planned for a future release.

---
