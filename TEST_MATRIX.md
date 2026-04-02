# S3 Encryption Client for Python — End-to-End Test Matrix

This document enumerates every customer-facing configuration option and input parameter,
then defines the matrix of combinations that must be tested end-to-end before launch.

---

## 1. Use Cases

| # | Use Case | Entry Point |
|---|----------|-------------|
| UC-1 | Encrypt and upload an object | `S3EncryptionClient.put_object(**kwargs)` |
| UC-2 | Download and decrypt an object | `S3EncryptionClient.get_object(**kwargs)` |
| UC-3 | Decrypt a legacy (V1/V2) object | `S3EncryptionClient.get_object(**kwargs)` with legacy-encrypted data |

---

## 2. Configuration Options (S3EncryptionClientConfig)

| Parameter | Type | Default | Valid Values | Notes |
|-----------|------|---------|--------------|-------|
| `keyring` | `AbstractKeyring` (required) | — | `KmsKeyring`, custom keyring | Determines key wrapping strategy |
| `encryption_algorithm` | `AlgorithmSuite` | `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY` | See §2a | Must not be legacy; validated against commitment policy |
| `commitment_policy` | `CommitmentPolicy` | `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` | See §2b | Controls key-commitment enforcement |
| `enable_legacy_unauthenticated_modes` | `bool` | `False` | `True` / `False` | Allows decryption of AES-CBC (V1) objects |
| `cmm` | `AbstractCryptoMaterialsManager` | `DefaultCryptoMaterialsManager(keyring)` | `DefaultCryptoMaterialsManager`, custom CMM | Auto-created from keyring if omitted |
| `instruction_file_suffix` | `str` | `".instruction"` | Any string | Suffix for instruction-file metadata strategy |
| `enable_delayed_authentication` | `bool` | `False` | `True` / `False` | Releases plaintext before GCM tag verification (streaming) |

### 2a. Algorithm Suites

| Enum Member | ID | Legacy? | Cipher | Key Commitment |
|-------------|----|---------|--------|----------------|
| `ALG_AES_256_CBC_IV16_NO_KDF` | 0x0070 | Yes | AES/CBC/PKCS5Padding | No |
| `ALG_AES_256_GCM_IV12_TAG16_NO_KDF` | 0x0072 | No | AES/GCM/NoPadding | No |
| `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY` | 0x0073 | No | AES/GCM/HKDF/CommitKey | Yes |

Legacy suites are rejected at config time for encryption; only allowed for decryption when `enable_legacy_unauthenticated_modes=True`.

### 2b. Commitment Policies

| Enum Member | Encrypt Constraint | Decrypt Constraint |
|-------------|--------------------|--------------------|
| `FORBID_ENCRYPT_ALLOW_DECRYPT` | Must NOT use committing suite | Allows any suite |
| `REQUIRE_ENCRYPT_ALLOW_DECRYPT` | Must use committing suite | Allows any suite |
| `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` | Must use committing suite | Must use committing suite |

---

## 3. KmsKeyring Configuration

| Parameter | Type | Default | Valid Values | Notes |
|-----------|------|---------|--------------|-------|
| `kms_client` | boto3 KMS client (required) | — | Any `botocore.client.BaseClient` for KMS | |
| `kms_key_id` | `str` (required) | — | Any valid KMS key ARN / alias | |
| `enable_legacy_wrapping_algorithms` | `bool` | `False` | `True` / `False` | Enables decryption of V1 `"kms"` wrapped keys |

Wrapping modes:
- `kms+context` — V2/V3 (always enabled)
- `kms` — V1 legacy (only when `enable_legacy_wrapping_algorithms=True`)

---

## 4. Per-Request Input Parameters

### 4a. put_object

| Parameter | Type | Required | Notes |
|-----------|------|----------|-------|
| `Bucket` | `str` | Yes | S3 bucket name |
| `Key` | `str` | Yes | S3 object key |
| `Body` | `bytes`, file-like, or `None` | No | Plaintext to encrypt; empty body if omitted |
| `EncryptionContext` | `dict[str, str]` | No | Additional authenticated data passed to KMS |
| *(all other S3 PutObject params)* | various | No | Passed through to boto3 |

### 4b. get_object

| Parameter | Type | Required | Notes |
|-----------|------|----------|-------|
| `Bucket` | `str` | Yes | S3 bucket name |
| `Key` | `str` | Yes | S3 object key |
| `EncryptionContext` | `dict[str, str]` | No | Must match context used at encryption time |
| *(all other S3 GetObject params)* | various | No | Passed through to boto3 |

---

## 5. Metadata Strategy (implicit)

The metadata strategy is determined by the encrypted object, not by a config flag:

| Strategy | How Detected | Relevant Config |
|----------|-------------|-----------------|
| Object metadata (header) | Encryption metadata present in S3 object metadata | — |
| Instruction file | Object metadata missing required keys | `instruction_file_suffix` on config |

---

## 6. End-to-End Test Matrix

### 6a. Encryption (put_object) — Required Combinations

| # | encryption_algorithm | commitment_policy | keyring | EncryptionContext | Body Type | Expected |
|---|----------------------|-------------------|---------|-------------------|-----------|----------|
| E1 | GCM_HKDF_COMMIT (default) | REQUIRE_ENCRYPT_REQUIRE_DECRYPT (default) | KmsKeyring | None | `bytes` | Success |
| E2 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | KmsKeyring | `{"k":"v"}` | `bytes` | Success |
| E3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_ALLOW_DECRYPT | KmsKeyring | None | `bytes` | Success |
| E4 | GCM_IV12_NO_KDF | FORBID_ENCRYPT_ALLOW_DECRYPT | KmsKeyring | None | `bytes` | Success |
| E5 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | KmsKeyring | None | `BytesIO` | Success |
| E6 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | KmsKeyring | None | `None` (empty) | Success |
| E7 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | Custom keyring | None | `bytes` | Success |
| E8 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | Custom CMM (no keyring) | None | `bytes` | Success |

### 6b. Decryption (get_object) — Required Combinations

| # | Object Format | Object Algorithm | commitment_policy | enable_legacy_unauth | enable_legacy_wrapping | enable_delayed_auth | EncryptionContext | Metadata Strategy | Expected |
|---|---------------|------------------|-------------------|----------------------|------------------------|---------------------|-------------------|-------------------|----------|
| D1 | V3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | False | False | False | None | Header | Success |
| D2 | V3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | False | False | False | `{"k":"v"}` | Header | Success |
| D3 | V3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | False | False | True | None | Header | Success (streaming) |
| D4 | V3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_ALLOW_DECRYPT | False | False | False | None | Header | Success |
| D5 | V3 | GCM_HKDF_COMMIT | FORBID_ENCRYPT_ALLOW_DECRYPT | False | False | False | None | Header | Success |
| D6 | V2 | GCM_IV12_NO_KDF | REQUIRE_ENCRYPT_ALLOW_DECRYPT | False | False | False | None | Header | Success |
| D7 | V2 | GCM_IV12_NO_KDF | FORBID_ENCRYPT_ALLOW_DECRYPT | False | False | False | None | Header | Success |
| D8 | V1 | CBC | REQUIRE_ENCRYPT_ALLOW_DECRYPT | True | True | False | None | Header | Success |
| D9 | V1 | CBC | FORBID_ENCRYPT_ALLOW_DECRYPT | True | True | False | None | Header | Success |
| D10 | V2 | GCM_IV12_NO_KDF | any | False | False | False | None | Instruction file | Success |
| D11 | V3 | GCM_HKDF_COMMIT | any | False | False | False | None | Instruction file | Success |
| D12 | V2 | GCM_IV12_NO_KDF | any | False | False | False | None | Instruction file (custom suffix) | Success |
| D13 | V3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | False | False | False | `{"k":"v"}` mismatched | Header | Success decrypt, context validation fails in keyring |

### 6c. Round-Trip Tests (put then get)

| # | encryption_algorithm | commitment_policy | EncryptionContext | Body Size | Notes |
|---|----------------------|-------------------|-------------------|-----------|-------|
| RT1 | GCM_HKDF_COMMIT (default) | REQUIRE_ENCRYPT_REQUIRE_DECRYPT (default) | None | Small (< 1 KB) | Happy path |
| RT2 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | `{"k":"v"}` | Small | With encryption context |
| RT3 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | None | Large (> 1 MB) | Streaming / chunked |
| RT4 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | None | 0 bytes | Empty body |
| RT5 | GCM_IV12_NO_KDF | FORBID_ENCRYPT_ALLOW_DECRYPT | None | Small | Non-committing suite |
| RT6 | GCM_HKDF_COMMIT | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | None | Small | Delayed authentication enabled |

---

## 7. Negative / Validation Cases (Invalid Inputs and Configurations)

### 7a. Encryption — Invalid Configurations

| # | encryption_algorithm | commitment_policy | Expected Error |
|---|----------------------|-------------------|----------------|
| EN1 | CBC (legacy) | any | Reject: cannot encrypt with legacy suite |
| EN2 | GCM_IV12_NO_KDF (non-committing) | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | Reject: policy requires committing suite |
| EN3 | GCM_IV12_NO_KDF (non-committing) | REQUIRE_ENCRYPT_ALLOW_DECRYPT | Reject: policy requires committing suite |
| EN4 | GCM_HKDF_COMMIT (committing) | FORBID_ENCRYPT_ALLOW_DECRYPT | Reject: policy forbids committing suite |

### 7b. Decryption — Invalid Configurations / Inputs

| # | Object Format | commitment_policy | enable_legacy_unauth | enable_legacy_wrapping | Expected Error |
|---|---------------|-------------------|----------------------|------------------------|----------------|
| DN1 | V1 (CBC) | any | False | any | Reject: legacy unauthenticated mode disabled |
| DN2 | V1 (CBC) | any | True | False | Reject: legacy wrapping algorithms disabled |
| DN3 | V2 (non-committing) | REQUIRE_ENCRYPT_REQUIRE_DECRYPT | False | False | Reject: policy requires committing suite on decrypt |
| DN4 | V3 | any | False | False | Reject: mismatched EncryptionContext |
| DN5 | V3 | any | False | False | Reject: EncryptionContext contains reserved key `aws:x-amz-cek-alg` |

### 7c. Instruction File — Invalid Inputs

| # | Scenario | Expected Error |
|---|----------|----------------|
| IF1 | Instruction file missing from S3 | Reject: instruction file not found |
| IF2 | Instruction file contains invalid / corrupt JSON | Reject: cannot parse instruction file |
| IF3 | Instruction file suffix does not match actual suffix in S3 | Reject: instruction file not found |
| IF4 | Instruction file exists but has no body | Reject: empty or missing instruction file body |

### 7d. General — Invalid Inputs

| # | Scenario | Expected Error |
|---|----------|----------------|
| G1 | `Body` is an unsupported type (e.g. `int`) | Reject: unexpected body type |
| G2 | `put_object` called while in instruction-file mode | Reject: instruction file mode not supported for put_object |
| G3 | Instruction file fetch with no `s3_client` available | Reject: s3_client required |
| G4 | Instruction file fetch with missing `Bucket` or `Key` | Reject: bucket and key required |

---

## 8. Streaming / Delayed Authentication

The `enable_delayed_authentication` flag controls whether GCM plaintext is released before or after tag verification. CBC content is always streamed (no auth tag). These cases verify the streaming behavior across modes and algorithm suites.

| # | Algorithm | Delayed Auth | Scenario | Expected |
|---|-----------|-------------|----------|----------|
| S1 | GCM (any) | False | Buffered mode withholds plaintext until GCM tag verified | Tag verified before any `.read()` returns data |
| S2 | GCM (any) | True | Delayed auth releases plaintext before tag verification | `.read()` returns data before tag is checked |
| S3 | GCM + KC-GCM | both | Both modes produce identical plaintext for same object | Byte-for-byte match |
| S4 | GCM + KC-GCM | both | Chunked / partial reads | Reassembled chunks equal original plaintext |
| S5 | GCM + KC-GCM | both | Empty body round-trip | Both modes handle 0-byte plaintext |
| S6 | GCM + KC-GCM | True | Large object (≥ 1 MB) streaming | Chunked delayed-auth reads produce correct plaintext |
| S7 | CBC | N/A | CBC always streams (no buffered mode) | Decryption succeeds regardless of flag |
| S8 | GCM (any) | False | Tampered ciphertext detected | Buffered mode raises error, no plaintext released |
| S9 | GCM (any) | True | Tampered tag detected | Delayed auth raises error after final read |

---

## 9. Cross-Cutting Concerns

These should be verified across multiple matrix entries:

| Concern | What to Verify |
|---------|----------------|
| Thread safety | Concurrent put_object / get_object calls share no state |
| Custom CMM | Encryption and decryption work when providing a CMM instead of a keyring |
| Custom keyring | A user-implemented `AbstractKeyring` subclass works end-to-end |
| Multi-region KMS keys | Encrypt in one region, decrypt in another |
| Error propagation | `S3EncryptionClientError` and `S3EncryptionClientSecurityError` surface correctly |
| Instruction file edge cases | Missing instruction file, corrupt instruction file, wrong suffix |
