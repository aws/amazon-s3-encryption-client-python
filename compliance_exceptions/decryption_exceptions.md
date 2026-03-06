# Compliance Exceptions for Decryption Implementation

## Summary

The Python S3 Encryption Client does not currently support Ranged Gets.
Ranged Gets allow downloading and decrypting a subset of bytes from an encrypted S3 object.
This is an optional feature per the specification ("MAY support") and is planned for a future release.

## Ranged Gets

##= specification/s3-encryption/decryption.md#ranged-gets
##= type=exception
##% The S3EC MAY support the "range" parameter on GetObject which specifies a subset of bytes to download and decrypt.

Justification: Ranged Gets are not yet implemented in the Python S3 Encryption Client. The specification uses MAY, making this an optional feature. This is planned for a future release.

---

##= specification/s3-encryption/decryption.md#ranged-gets
##= type=exception
##% If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning and end of the cipher blocks for the given range.

Justification: Not applicable since Ranged Gets are not yet supported. When Ranged Gets are implemented, this requirement will be fulfilled.

---

##= specification/s3-encryption/decryption.md#ranged-gets
##= type=exception
##% If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.

Justification: Not applicable since Ranged Gets are not yet supported. When Ranged Gets are implemented, the correct CTR-mode algorithm suite will be used for GCM-encrypted objects.

---

##= specification/s3-encryption/decryption.md#ranged-gets
##= type=exception
##% If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.

Justification: Not applicable since Ranged Gets are not yet supported. When Ranged Gets are implemented, the correct CTR-mode algorithm suite will be used for key-committing objects.

---

##= specification/s3-encryption/decryption.md#ranged-gets
##= type=exception
##% If the GetObject response contains a range, but the GetObject request does not contain a range, the S3EC MUST throw an exception.

Justification: Not applicable since Ranged Gets are not yet supported. When Ranged Gets are implemented, this validation will be added to detect unexpected range responses.

---
