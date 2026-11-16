# Compliance Exceptions for KMS Keyring Implementation

## Summary

The Python S3 Encryption Client implementation takes a pragmatic approach that:
1. Simplifies the keyring architecture by not implementing the full abstract method pattern (GenerateDataKey, EncryptDataKey, DecryptDataKey)
2. Defers validation to the AWS SDK where appropriate (key identifier validation)
3. Uses more efficient KMS API patterns (GenerateDataKey instead of separate Generate + Encrypt)
4. Omits optional features like custom User Agent strings (planned for future enhancement)

## TODOs

##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
##= type=TODO
##% - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.

##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
##= type=TODO
##% - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.

## Initialization Validation

##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
##= type=exception
##% The KmsKeyring MAY validate that the AWS KMS key identifier is not null or empty.

Justification: This validation is not implemented. The Python implementation relies on attrs field validation and KMS SDK to catch invalid key identifiers. 

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
##= type=exception
##% If the KmsKeyring validates that the AWS KMS key identifier is not null or empty, then it MUST throw an exception.

Justification: Not applicable since the MAY validation above is not implemented. If we don't validate, we don't need to throw an exception for validation failure.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
##= type=exception
##% The KmsKeyring MAY validate that the AWS KMS key identifier is [a valid AWS KMS Key identifier](../../framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-identifier).

Justification: This validation is not implemented. The Python implementation defers validation to the AWS KMS SDK, which will return an error if the key identifier is invalid. 

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
##= type=exception
##% If the KmsKeyring validates that the AWS KMS key identifier is not a valid AWS KMS Key identifier, then it MUST throw an exception.

Justification: Not applicable since the MAY validation above is not implemented. If we don't validate, we don't need to throw an exception for validation failure.

---

## EncryptDataKey Method

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% The KmsKeyring MUST implement the EncryptDataKey method.

Justification: The Python implementation does not define a separate EncryptDataKey method. Instead, the encryption logic is directly implemented in the on_encrypt method using KMS GenerateDataKey API, which both generates and encrypts the data key in a single call. This is more efficient than the spec's pattern of separate Generate + Encrypt calls.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.

Justification: The Python implementation uses KMS GenerateDataKey instead of KMS Encrypt. GenerateDataKey is more efficient as it generates and encrypts the data key in a single API call, rather than requiring separate generation and encryption operations. This reduces latency and API call count.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% - `KeyId` MUST be the configured AWS KMS key identifier.

Justification: This requirement is for the KMS Encrypt API call. Since the Python implementation uses GenerateDataKey instead of Encrypt, this specific requirement doesn't apply. However, the KeyId parameter is correctly passed to GenerateDataKey.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).

Justification: The Python implementation uses KMS GenerateDataKey instead of Encrypt. GenerateDataKey generates the plaintext key itself, so there is no pre-existing plaintext data key to pass in. The Plaintext parameter doesn't exist in the GenerateDataKey API - instead, the API returns both the plaintext and encrypted versions of the newly generated key.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [encryption materials](../structures.md#encryption-materials).

Justification: This requirement is for the KMS Encrypt API call. Since the Python implementation uses GenerateDataKey instead of Encrypt, this specific requirement doesn't apply. However, the EncryptionContext parameter is correctly passed to GenerateDataKey.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.

Justification: Custom User Agent strings are not currently implemented. This is a future enhancement for better observability and metrics tracking. The functionality works correctly without it, but metrics attribution to the S3 Encryption Client would be improved with this addition.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.

Justification: This requirement is for the KMS Encrypt API call. Since the Python implementation uses GenerateDataKey instead of Encrypt, this specific requirement doesn't apply. However, the implementation does correctly fail when GenerateDataKey fails.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
##= type=exception
##% If the call to AWS KMS Encrypt is successful, OnEncrypt MUST return the `CiphertextBlob` as a collection of bytes.

Justification: This requirement is for the KMS Encrypt API call. Since the Python implementation uses GenerateDataKey instead of Encrypt, this specific requirement doesn't apply. However, the implementation does correctly return the CiphertextBlob from GenerateDataKey's response.

---

## DecryptDataKey Method Structure

##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
##= type=exception
##% - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.

Justification: Custom User Agent strings are not currently implemented for KMS Decrypt calls. This is a future enhancement for better observability and metrics tracking.

---

##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
##= type=exception
##% - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.

Justification: Custom User Agent strings are not currently implemented for KMS Decrypt calls in Kms+Context mode. This is a future enhancement for better observability and metrics tracking.

---

## S3 Keyring Abstract Methods

##= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
##= type=exception
##% - The S3 Keyring MUST define an abstract method GenerateDataKey.

Justification: The S3Keyring base class does not define abstract methods for GenerateDataKey, EncryptDataKey, or DecryptDataKey. The Python implementation uses a simpler design where concrete keyrings (like KmsKeyring) directly implement the on_encrypt and on_decrypt methods without the intermediate abstraction layer. This reduces complexity for the initial implementation.

---

##= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
##= type=exception
##% - The S3 Keyring MUST define an abstract method EncryptDataKey.

Justification: The S3Keyring base class does not define abstract methods for GenerateDataKey, EncryptDataKey, or DecryptDataKey. 
The Python implementation uses a simpler design where concrete keyrings (like KmsKeyring) directly implement the on_encrypt and on_decrypt methods without the intermediate abstraction layer.

---

##= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
##= type=exception
##% - The S3 Keyring MUST define an abstract method DecryptDataKey.

Justification: The S3Keyring base class does not define abstract methods for GenerateDataKey, EncryptDataKey, or DecryptDataKey. 
The Python implementation uses a simpler design where concrete keyrings (like KmsKeyring) directly implement the on_encrypt and on_decrypt methods without the intermediate abstraction layer.

---

## S3 Keyring OnEncrypt Logic

##= specification/s3-encryption/materials/s3-keyring.md#onencrypt
##= type=exception
##% If the Plaintext Data Key in the input EncryptionMaterials is null, the S3 Keyring MUST call the GenerateDataKey method using the materials.

Justification: The S3Keyring base class does not implement this logic. The concrete KmsKeyring implementation directly calls KMS Encrypt in its on_encrypt method. 
The specification's pattern of checking for null plaintext and conditionally calling GenerateDataKey is not followed; instead, the implementation always generates a new key.

---

##= specification/s3-encryption/materials/s3-keyring.md#onencrypt
##= type=exception
##% If the materials returned from GenerateDataKey contain an EncryptedDataKey, the S3 Keyring MUST return the materials.

Justification: Not applicable since the GenerateDataKey method pattern is not implemented. The KmsKeyring directly handles key generation and encryption in on_encrypt.

---

##= specification/s3-encryption/materials/s3-keyring.md#onencrypt
##= type=exception
##% If the materials returned from GenerateDataKey do not contain an EncryptedDataKey, the S3 Keyring MUST call the EncryptDataKey method using the materials.

Justification: Not applicable since the GenerateDataKey and EncryptDataKey method pattern is not implemented. 
The KmsKeyring uses KMS GenerateDataKey which returns both plaintext and encrypted key in a single call.

---

## S3 Keyring OnDecrypt Validations

##= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
##= type=exception
##% The S3 Keyring MAY validate that the Key Provider ID of the Encrypted Data Key matches the expected default Key Provider ID value.

Justification: This optional validation is not implemented. 
The Key Provider ID field is not used for anything in S3EC. 

---

##= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
##= type=exception
##% The S3 Keyring MUST call the DecryptDataKey method using the materials and add the resulting plaintext data key to the materials.

Justification: The S3Keyring base class does not implement this logic. 
The concrete KmsKeyring implementation directly calls KMS Decrypt in its on_decrypt method rather than calling a separate DecryptDataKey method. 
This is consistent with the simplified design that doesn't use the abstract method pattern.

---
