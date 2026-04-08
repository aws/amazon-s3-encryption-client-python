# S3 Encryption Client — Test Matrix Evaluation

Maps each test case from `TEST_MATRIX.md` to existing tests in the codebase.
<<<<<<< HEAD
=======
"TODO" means no existing test was found for that case.
>>>>>>> 3ddb5ebdec495b464691b9ae15e31972443d97e5

---

## Encryption (put_object) — Positive Cases

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| E1 | Default config, KmsKeyring, bytes body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[KC_GCM]` |
| E2 | Default config + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| E3 | REQUIRE_ENCRYPT_ALLOW_DECRYPT + committing suite | ✅ Covered | Both | Unit: `test/test_default_algorithm_commitment.py::test_default_encryption_decryptable_with_require_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies[writer=REQUIRE_ALLOW]` |
| E4 | GCM_IV12_NO_KDF + FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[AES_GCM]` |
| E5 | BytesIO body | ✅ Covered | Both | Unit: `test/test_encryption.py::TestContentEncryption::test_bytesio_body_encrypts_successfully`; Integration: `test/integration/test_i_s3_encryption.py::test_bytesio_body_roundtrip` |
| E6 | None / empty body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_no_body_roundtrip` |
| E7 | Custom keyring | ✅ Covered | Integration | `test/integration/test_i_custom_keyring_cmm.py::TestCustomKeyring::test_roundtrip_with_custom_keyring` and `test_roundtrip_with_custom_keyring_aes_gcm` |
| E8 | Custom CMM (no keyring) | ✅ Covered | Integration | `test/integration/test_i_custom_keyring_cmm.py::TestCustomCMM::test_roundtrip_with_custom_cmm` and `test_roundtrip_with_custom_cmm_aes_gcm` |

---

## Decryption (get_object) — Positive Cases

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| D1 | V3 GCM_HKDF_COMMIT, REQUIRE_REQUIRE, header | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_require_allows_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_require_require_decrypts_committing` |
| D2 | V3 + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| D3 | V3 + delayed auth | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_roundtrip[KC_GCM]` |
| D4 | V3, REQUIRE_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_encrypt_allow_decrypt_allows_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_require_encrypt_allow_decrypt_decrypts_committing` |
| D5 | V3, FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_forbid_encrypt_allow_decrypt_allows_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_forbid_encrypt_allow_decrypt_decrypts_committing` |
| D6 | V2 GCM, REQUIRE_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_encrypt_allow_decrypt_allows_non_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_require_encrypt_allow_decrypt_decrypts_non_committing` |
| D7 | V2 GCM, FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_forbid_encrypt_allows_non_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_forbid_encrypt_allow_decrypt_decrypts_non_committing` |
| D8 | V1 CBC, legacy enabled, legacy wrapping enabled | ✅ Covered | Unit | `test/test_decryption.py::TestCBCDecryption::test_cbc_decryption_succeeds_when_legacy_enabled` |
| D9 | V1 CBC, FORBID_ENCRYPT_ALLOW_DECRYPT + legacy | ✅ Covered | Unit | Same as D8 (uses FORBID_ENCRYPT_ALLOW_DECRYPT) |
| D10 | V2 GCM via instruction file | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_v2_from_instruction_file`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v2_instruction_file` |
| D11 | V3 via instruction file | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_v3_from_instruction_file`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v3_instruction_file` |
| D12 | V2 instruction file, custom suffix | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_with_custom_instruction_file_suffix`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v2_instruction_file_custom_suffix` |
| D13 | V3 + mismatched EncryptionContext | ✅ Covered | Both | Unit: `test/test_kms_keyring.py::test_on_decrypt_fails_with_mismatched_encryption_context`; Integration: `test/integration/test_i_s3_encryption.py::test_encryption_context_mismatch` |

---

## Round-Trip Tests

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| RT1 | Default config, small body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[KC_GCM]` |
| RT2 | Default config + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| RT3 | Large body (> 1 MB) | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_large_object` (1 MB) |
| RT4 | Empty body (0 bytes) | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_empty_body_roundtrip` |
| RT5 | GCM_IV12_NO_KDF + FORBID | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[AES_GCM]` |
| RT6 | Delayed authentication | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_roundtrip` |

---

## Negative / Validation Cases — Encryption

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| EN1 | Reject legacy suite for encryption | ✅ Covered | Unit | `test/test_key_commitment_encrypt.py` — legacy CBC rejected at config time |
| EN2 | GCM_IV12 + REQUIRE_ENCRYPT_REQUIRE_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::test_require_encrypt_require_decrypt_rejects_non_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_require_encrypt_require_decrypt_rejects_non_committing` |
| EN3 | GCM_IV12 + REQUIRE_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::test_require_encrypt_allow_decrypt_rejects_non_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_require_encrypt_allow_decrypt_rejects_non_committing` |
| EN4 | GCM_HKDF_COMMIT + FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::test_forbid_encrypt_allow_decrypt_rejects_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_forbid_encrypt_allow_decrypt_rejects_committing` |

---

## Negative / Validation Cases — Decryption

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| DN1 | V1 CBC rejected when legacy disabled | ✅ Covered | Unit | `test/test_decryption.py::TestCBCDecryption::test_cbc_object_rejected_when_legacy_disabled` |
| DN2 | V1 CBC, legacy enabled but legacy wrapping disabled | ✅ Covered | Unit | `test/test_kms_keyring.py::test_on_decrypt_rejects_kms_v1_when_legacy_disabled` |
| DN3 | V2 non-committing + REQUIRE_REQUIRE | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_require_rejects_non_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_require_require_rejects_non_committing` |
| DN4 | Mismatched EncryptionContext | ✅ Covered | Both | Unit: `test/test_kms_keyring.py::test_on_decrypt_fails_with_mismatched_encryption_context`; Integration: `test/integration/test_i_s3_encryption.py::test_encryption_context_mismatch` |
| DN5 | Reserved key in EncryptionContext | ✅ Covered | Unit | `test/test_kms_keyring.py::test_on_decrypt_rejects_reserved_key_in_request_context` |

---

## Negative / Validation Cases — Instruction File

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| IF1 | Instruction file missing from S3 | ✅ Covered | Unit | `test/test_pipelines.py::test_decrypt_instruction_file_s3_not_found_raises` |
| IF2 | Instruction file contains invalid JSON | ✅ Covered | Both | Unit: `test/test_s3_encryption_client_plugin.py::test_instruction_file_mode_invalid_json_raises_error`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_invalid_instruction_file` |
| IF3 | Instruction file suffix mismatch | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_instruction_file_wrong_suffix_raises` |
| IF4 | Instruction file exists but has no body | ✅ Covered | Unit | `test/test_pipelines.py::test_decrypt_instruction_file_empty_metadata_raises` |

---

## Negative / Validation Cases — General

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| G1 | Unsupported Body type | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_invalid_body_types` |
| G2 | put_object in instruction-file mode | ✅ Covered | Unit | `test/test_s3_encryption_client_plugin.py::test_put_object_rejects_instruction_file_mode` |
| G3 | Instruction file fetch with no s3_client | ✅ Covered | Unit | `test/test_pipelines.py::test_decrypt_instruction_file_no_s3_client_raises` |
| G4 | Instruction file fetch with missing Bucket/Key | ✅ Covered | Unit | `test/test_pipelines.py::test_decrypt_instruction_file_missing_bucket_key_raises` |
| G5 | Non-ASCII EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_non_ascii_encryption_context_rejected` |
| G6 | Inaccessible KMS key (AccessDenied) | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_inaccessible_kms_key_raises_access_denied` |
| G7 | GetObject on nonexistent S3 key | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_get_nonexistent_object_raises_no_such_key` |

---

## Streaming / Delayed Authentication

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| S1 | Buffered withholds plaintext until tag verified | ✅ Covered | Unit | `test/test_stream.py::TestBufferedWithholdsUntilVerification` |
| S2 | Delayed auth releases plaintext before tag verification | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthReleasesBeforeVerification` |
| S3 | Both modes produce identical plaintext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_buffered_and_delayed_produce_same_plaintext` |
| S4 | Chunked / partial reads | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_buffered_partial_reads` and `test_delayed_auth_chunked_reads` |
| S5 | Empty body round-trip both modes | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_empty_body_roundtrip` |
| S6 | Large object delayed-auth streaming | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_large_object` |
| S7 | CBC always streams regardless of flag | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthCBCDecryption` |
| S8 | Tampered ciphertext detected (buffered) | ✅ Covered | Unit | `test/test_stream.py::TestBufferedDecryptingStream::test_tampered_ciphertext_raises_error` |
| S9 | Tampered tag detected (delayed auth) | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthGCMDecryption::test_tampered_tag_raises_error` |

---

## S3 Interoperability

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| S3-1 | S3 passthrough options preserved | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_s3_passthrough_options_preserved` |
| S3-2 | CopyObject then decrypt | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_copy_object_then_decrypt` |

---

## Multi-Region Key (MRK) Cross-Region

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| MRK-1 | Encrypt primary, decrypt replica | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py::test_encrypt_primary_decrypt_replica` |
| MRK-2 | Encrypt replica, decrypt primary | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py::test_encrypt_replica_decrypt_primary` |
| MRK-3 | Round-trip with MRK primary | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py::test_encrypt_and_decrypt_same_region_primary` |
| MRK-4 | Round-trip with MRK replica | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py::test_encrypt_and_decrypt_same_region_replica` |
| MRK-5 | Non-replicated region fails | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py::test_decrypt_with_wrong_region_kms_client_fails` |

---

## Cross-Cutting Concerns

| Concern | Status | Type | Test Location |
|---------|--------|------|---------------|
| Thread safety | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_multithreaded.py` (3 tests) |
| Custom CMM | ✅ Covered | Integration | `test/integration/test_i_custom_keyring_cmm.py::TestCustomCMM` |
| Custom keyring | ✅ Covered | Integration | `test/integration/test_i_custom_keyring_cmm.py::TestCustomKeyring` |
| Multi-region KMS keys | ✅ Covered | Integration | `test/integration/test_i_mrk_cross_region.py` (5 tests) |
| Error propagation | ✅ Covered | Both | Unit: `test/test_exceptions.py`; Integration: `test_inaccessible_kms_key_raises_access_denied`, `test_get_nonexistent_object_raises_no_such_key` |
| Instruction file edge cases | ✅ Covered | Both | Unit: invalid JSON, invalid keys, missing file, empty body; Integration: invalid file, wrong suffix |

---

## Summary

- Total test cases: 66 (E1–E8, D1–D13, RT1–RT6, EN1–EN4, DN1–DN5, IF1–IF4, G1–G7, S1–S9, S3-1–S3-2, MRK-1–MRK-5)
- Covered: 66
- TODO: 0
