# Compliance Exceptions for Key Commitment Policy — Encryption Side

## Summary

The Python S3 Encryption Client does not yet explicitly validate the commitment policy
against the configured algorithm suite on the encryption path. The client defaults to the
key-committing algorithm suite (`ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`) and validates
that legacy (CBC) suites cannot be configured, but does not enforce the full matrix of
commitment policy vs. algorithm suite at encryption time.

## FORBID_ENCRYPT_ALLOW_DECRYPT — Encrypt Restriction

##= specification/s3-encryption/key-commitment.md#commitment-policy
##= type=exception
##% When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.

Justification: The encryption path does not validate the commitment policy against the algorithm suite. A caller who configures `FORBID_ENCRYPT_ALLOW_DECRYPT` but leaves the default committing algorithm suite would incorrectly encrypt with a committing suite. This validation is planned for a future release.

---

## REQUIRE_ENCRYPT_ALLOW_DECRYPT — Encrypt Restriction

##= specification/s3-encryption/key-commitment.md#commitment-policy
##= type=exception
##% When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.

Justification: The encryption path does not explicitly validate that the algorithm suite supports key commitment when the policy is `REQUIRE_ENCRYPT_ALLOW_DECRYPT`. In practice, the default algorithm suite is the committing suite, so this is satisfied by default. However, there is no guard preventing a caller from overriding the algorithm suite to a non-committing one. This validation is planned for a future release.

---

## REQUIRE_ENCRYPT_REQUIRE_DECRYPT — Encrypt Restriction

##= specification/s3-encryption/key-commitment.md#commitment-policy
##= type=exception
##% When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.

Justification: Same as above. The default algorithm suite is the committing suite, so this is satisfied by default, but there is no explicit validation preventing a non-committing suite from being configured. This validation is planned for a future release.

---
